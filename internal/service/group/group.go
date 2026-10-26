package group

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
)

type groupService struct {
	repo      repository.IGroupRepository
	tenantSvc tenant.ITenantService // 注入租户服务：创建组前读取 MaxUserGroups 做配额强制校验 (R2.6)
	userRepo  repository.IUserRepository
	enforcer  *casbin.SyncedEnforcer
}

func NewGroupService(repo repository.IGroupRepository, tenantSvc tenant.ITenantService, userRepo repository.IUserRepository, enforcer *casbin.SyncedEnforcer) IGroupService {
	return &groupService{
		repo:      repo,
		tenantSvc: tenantSvc,
		userRepo:  userRepo,
		enforcer:  enforcer,
	}
}

func (s *groupService) Create(ctx context.Context, g domain.Group) (int64, error) {
	// 写操作防缺失租户上下文：与 gormx 租户插件形成纵深防御——插件负责数据行过滤，
	// 这里显式业务拒绝，避免 tid<=0 时配额读取与组计数被静默绕过
	tid := ctxutil.GetTenantID(ctx).Int64()
	if tid <= 0 {
		return 0, errs.ErrMissingTenantContext
	}

	// 配额校验 (R2.6/R2.7)：MaxUserGroups <= 0 视为无限制，只有 > 0 才计数拦截；
	// 组计数复用 List 的 total 返回并限定 limit=1，避免为校验拉取全量数据
	t, err := s.tenantSvc.GetByID(ctx, tid)
	if err != nil {
		return 0, fmt.Errorf("查询租户配额失败: %w", err)
	}
	if quota := t.MaxUserGroups; quota > 0 {
		_, total, err := s.repo.List(ctx, 0, 1)
		if err != nil {
			return 0, fmt.Errorf("统计用户组数量失败: %w", err)
		}
		if total >= quota {
			return 0, errs.ErrTenantQuotaExceeded
		}
	}

	return s.repo.Create(ctx, g)
}

func (s *groupService) Update(ctx context.Context, g domain.Group) error {
	_, err := s.repo.Update(ctx, g)
	if err != nil {
		return fmt.Errorf("更新用户组失败: %w", err)
	}
	return nil
}

func (s *groupService) Delete(ctx context.Context, id int64) error {
	group, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("查询用户组失败: %w", err)
	}

	tid := ctxutil.GetTenantID(ctx).Int64()

	// 1. 删除组实体和数据库中的成员关联
	if err = s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("删除用户组失败: %w", err)
	}

	// 2. 清除 Casbin 规则
	// 2.1 清除用户加入组的规则：g, user:xxx, group:code, tid
	_, _ = s.enforcer.RemoveFilteredGroupingPolicy(domain.CasbinObjectIndex, domain.GroupSubject(group.Code), strconv.FormatInt(tid, 10))

	// 2.2 清除组关联角色的规则：g, group:code, role:xxx, tid
	_, _ = s.enforcer.RemoveFilteredGroupingPolicy(domain.CasbinSubjectIndex, domain.GroupSubject(group.Code), "", strconv.FormatInt(tid, 10))

	return nil
}

func (s *groupService) List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error) {
	return s.repo.List(ctx, offset, limit)
}

func (s *groupService) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error) {
	return s.repo.Search(ctx, keyword, offset, limit)
}

func (s *groupService) CountSearch(ctx context.Context, keyword string) (int64, error) {
	return s.repo.CountSearch(ctx, keyword)
}

func (s *groupService) GetByCode(ctx context.Context, code string) (domain.Group, error) {
	return s.repo.GetByCode(ctx, code)
}

func (s *groupService) AssignMembers(ctx context.Context, groupCode string, usernames []string) (bool, error) {
	if len(usernames) == 0 {
		return true, nil
	}

	// 1. 获取组详情
	group, err := s.repo.GetByCode(ctx, groupCode)
	if err != nil {
		return false, fmt.Errorf("查询用户组失败: %w", err)
	}

	// 2. 批量查找用户 ID
	users, err := s.userRepo.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return false, fmt.Errorf("批量查询用户失败: %w", err)
	}

	userIDs := make([]int64, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	// 3. 写入 GORM 关系表
	if err = s.repo.BindMembers(ctx, group.ID, userIDs); err != nil {
		return false, fmt.Errorf("绑定组成员失败: %w", err)
	}

	// 4. 批量向 Casbin 添加分组策略
	tid := ctxutil.GetTenantID(ctx).Int64()
	policies := make([][]string, 0, len(usernames))
	for _, username := range usernames {
		policies = append(policies, []string{
			domain.UserSubject(username),
			domain.GroupSubject(groupCode),
			strconv.FormatInt(tid, 10),
		})
	}

	return s.enforcer.AddGroupingPolicies(policies)
}

func (s *groupService) RemoveMembers(ctx context.Context, groupCode string, usernames []string) (bool, error) {
	if len(usernames) == 0 {
		return true, nil
	}

	// 1. 获取组详情
	group, err := s.repo.GetByCode(ctx, groupCode)
	if err != nil {
		return false, fmt.Errorf("查询用户组失败: %w", err)
	}

	// 2. 批量查找用户 ID
	users, err := s.userRepo.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return false, fmt.Errorf("批量查询用户失败: %w", err)
	}

	userIDs := make([]int64, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	// 3. 解绑 GORM 关系
	if err = s.repo.UnbindMembers(ctx, group.ID, userIDs); err != nil {
		return false, fmt.Errorf("解绑组成员失败: %w", err)
	}

	// 4. 批量向 Casbin 移除分组策略
	tid := ctxutil.GetTenantID(ctx).Int64()
	policies := make([][]string, 0, len(usernames))
	for _, username := range usernames {
		policies = append(policies, []string{
			domain.UserSubject(username),
			domain.GroupSubject(groupCode),
			strconv.FormatInt(tid, 10),
		})
	}

	return s.enforcer.RemoveGroupingPolicies(policies)
}

func (s *groupService) ListMembers(ctx context.Context, groupCode string, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	group, err := s.repo.GetByCode(ctx, groupCode)
	if err != nil {
		return nil, 0, fmt.Errorf("查询用户组失败: %w", err)
	}

	return s.repo.ListMembers(ctx, group.ID, offset, limit, keyword)
}

func (s *groupService) ListAttachedGroupsByUser(ctx context.Context, username string, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	if userID == 0 && username == "" {
		return nil, 0, nil
	}

	if userID == 0 {
		user, err := s.userRepo.FindByUsername(ctx, username)
		if err != nil {
			return nil, 0, fmt.Errorf("查询用户失败: %w", err)
		}
		userID = user.ID
	}

	return s.repo.ListGroupsByUserID(ctx, userID, offset, limit, keyword)
}

func (s *groupService) ListAttachedGroupsByRole(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	if roleCode == "" {
		return nil, 0, nil
	}

	tid := ctxutil.GetTenantID(ctx).Int64()
	policies, err := s.enforcer.GetFilteredGroupingPolicy(1, domain.RoleSubject(roleCode), strconv.FormatInt(tid, 10))
	if err != nil {
		return nil, 0, err
	}

	groupCodes := make([]string, 0, len(policies))
	for _, policy := range policies {
		if len(policy) > 0 {
			groupCodes = append(groupCodes, domain.ExtractGroupCode(policy[0]))
		}
	}

	if len(groupCodes) == 0 {
		return nil, 0, nil
	}

	return s.repo.ListGroupsByCodes(ctx, groupCodes, offset, limit, keyword)
}

func (s *groupService) AssignRole(ctx context.Context, groupCode string, roleCode string) (bool, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	return s.enforcer.AddGroupingPolicy(
		domain.GroupSubject(groupCode),
		domain.RoleSubject(roleCode),
		strconv.FormatInt(tid, 10),
	)
}

func (s *groupService) RemoveRole(ctx context.Context, groupCode string, roleCode string) (bool, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	return s.enforcer.RemoveGroupingPolicy(
		domain.GroupSubject(groupCode),
		domain.RoleSubject(roleCode),
		strconv.FormatInt(tid, 10),
	)
}

func (s *groupService) ListRoles(ctx context.Context, groupCode string) ([]string, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	policies, err := s.enforcer.GetFilteredGroupingPolicy(0, domain.GroupSubject(groupCode), "", strconv.FormatInt(tid, 10))
	if err != nil {
		return nil, err
	}

	roleCodes := make([]string, 0, len(policies))
	for _, policy := range policies {
		if len(policy) > 1 {
			roleCodes = append(roleCodes, domain.ExtractRoleCode(policy[1]))
		}
	}
	return roleCodes, nil
}
