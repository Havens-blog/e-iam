package group

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quotaRBACModel 与生产 ioc/casbin.go 的 RBAC 模型保持一致（g = _, _, _），
// 仅用于本文件内构造内存 Casbin 引擎；独立命名避免与其他测试文件冲突。
const quotaRBACModel = `[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, "ANY") && r.obj == p.obj`

// newQuotaEnforcer 构造内存版 SyncedEnforcer（关闭 AutoSave，避免触碰
// string adapter 的未实现方法）。
func newQuotaEnforcer(t *testing.T) *casbin.SyncedEnforcer {
	t.Helper()
	m, err := model.NewModelFromString(quotaRBACModel)
	require.NoError(t, err)
	e, err := casbin.NewSyncedEnforcer(m, stringadapter.NewAdapter("# seed"))
	require.NoError(t, err)
	e.EnableAutoSave(false)
	return e
}

// quotaFakeRepo 是 IGroupRepository 的函数字段式替身，仅覆盖本文件各测试
// 所需的方法；独立命名保证本文件自包含可提交。
type quotaFakeRepo struct {
	repository.IGroupRepository
	listFn               func(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error)
	createFn             func(ctx context.Context, g domain.Group) (int64, error)
	updateFn             func(ctx context.Context, g domain.Group) (int64, error)
	getByIDFn            func(ctx context.Context, id int64) (domain.Group, error)
	deleteFn             func(ctx context.Context, id int64) error
	searchFn             func(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error)
	countSearchFn        func(ctx context.Context, keyword string) (int64, error)
	getByCodeFn          func(ctx context.Context, code string) (domain.Group, error)
	bindMembersFn        func(ctx context.Context, groupID int64, userIDs []int64) error
	unbindMembersFn      func(ctx context.Context, groupID int64, userIDs []int64) error
	listMembersFn        func(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]domain.User, int64, error)
	listGroupsByUserIDFn func(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error)
	listGroupsByCodesFn  func(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]domain.Group, int64, error)
}

func (f *quotaFakeRepo) List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error) {
	if f.listFn != nil {
		return f.listFn(ctx, offset, limit)
	}
	return nil, 0, nil
}

func (f *quotaFakeRepo) Create(ctx context.Context, g domain.Group) (int64, error) {
	if f.createFn != nil {
		return f.createFn(ctx, g)
	}
	return 1, nil
}

func (f *quotaFakeRepo) Update(ctx context.Context, g domain.Group) (int64, error) {
	if f.updateFn != nil {
		return f.updateFn(ctx, g)
	}
	return g.ID, nil
}

func (f *quotaFakeRepo) GetByID(ctx context.Context, id int64) (domain.Group, error) {
	if f.getByIDFn != nil {
		return f.getByIDFn(ctx, id)
	}
	return domain.Group{ID: id, Code: "dev-group"}, nil
}

func (f *quotaFakeRepo) Delete(ctx context.Context, id int64) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, id)
	}
	return nil
}

func (f *quotaFakeRepo) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error) {
	if f.searchFn != nil {
		return f.searchFn(ctx, keyword, offset, limit)
	}
	return nil, nil
}

func (f *quotaFakeRepo) CountSearch(ctx context.Context, keyword string) (int64, error) {
	if f.countSearchFn != nil {
		return f.countSearchFn(ctx, keyword)
	}
	return 0, nil
}

func (f *quotaFakeRepo) GetByCode(ctx context.Context, code string) (domain.Group, error) {
	if f.getByCodeFn != nil {
		return f.getByCodeFn(ctx, code)
	}
	return domain.Group{ID: 9, Code: code}, nil
}

func (f *quotaFakeRepo) BindMembers(ctx context.Context, groupID int64, userIDs []int64) error {
	if f.bindMembersFn != nil {
		return f.bindMembersFn(ctx, groupID, userIDs)
	}
	return nil
}

func (f *quotaFakeRepo) UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error {
	if f.unbindMembersFn != nil {
		return f.unbindMembersFn(ctx, groupID, userIDs)
	}
	return nil
}

func (f *quotaFakeRepo) ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	if f.listMembersFn != nil {
		return f.listMembersFn(ctx, groupID, offset, limit, keyword)
	}
	return nil, 0, nil
}

func (f *quotaFakeRepo) ListGroupsByUserID(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	if f.listGroupsByUserIDFn != nil {
		return f.listGroupsByUserIDFn(ctx, userID, offset, limit, keyword)
	}
	return nil, 0, nil
}

func (f *quotaFakeRepo) ListGroupsByCodes(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	if f.listGroupsByCodesFn != nil {
		return f.listGroupsByCodesFn(ctx, codes, offset, limit, keyword)
	}
	return nil, 0, nil
}

var _ repository.IGroupRepository = (*quotaFakeRepo)(nil)

// quotaFakeUserRepo 是 IUserRepository 的函数字段式替身，仅覆盖组成员/
// 附属组查询所需的两个方法。
type quotaFakeUserRepo struct {
	repository.IUserRepository
	findUsersByUsernamesFn func(ctx context.Context, usernames []string) ([]domain.User, error)
	findByUsernameFn       func(ctx context.Context, username string) (domain.User, error)
}

func (f *quotaFakeUserRepo) FindUsersByUsernames(ctx context.Context, usernames []string) ([]domain.User, error) {
	if f.findUsersByUsernamesFn != nil {
		return f.findUsersByUsernamesFn(ctx, usernames)
	}
	return nil, nil
}

func (f *quotaFakeUserRepo) FindByUsername(ctx context.Context, username string) (domain.User, error) {
	if f.findByUsernameFn != nil {
		return f.findByUsernameFn(ctx, username)
	}
	return domain.User{}, nil
}

var _ repository.IUserRepository = (*quotaFakeUserRepo)(nil)

// quotaFakeTenantSvc 是 ITenantService 的函数字段式替身，仅覆盖配额读取所需的
// GetByID；独立命名避免与租户域测试的替身混淆。
type quotaFakeTenantSvc struct {
	tenant.ITenantService
	getByIdFn func(ctx context.Context, id int64) (domain.Tenant, error)
}

func (f *quotaFakeTenantSvc) GetByID(ctx context.Context, id int64) (domain.Tenant, error) {
	if f.getByIdFn != nil {
		return f.getByIdFn(ctx, id)
	}
	return domain.Tenant{}, nil
}

var _ tenant.ITenantService = (*quotaFakeTenantSvc)(nil)

// TestGroupService_CreateQuotaEnforcement 验证创建用户组前的租户配额强制校验
// （tenant-management 规格 R2.6/R2.7）：仅当 MaxUserGroups > 0 且当前组数已达
// 上限时拒绝并返回 ErrTenantQuotaExceeded；配额 0/负数视为无限制直接放行且
// 不产生计数查询；缺失租户上下文走 fail-closed。
func TestGroupService_CreateQuotaEnforcement(t *testing.T) {
	testCases := []struct {
		name      string
		tid       int64
		tenant    domain.Tenant
		tenantErr error
		total     int64
		listErr   error
		wantErr   error
	}{
		{
			name:   "配额未设(0)视为无限制放行",
			tid:    2,
			tenant: domain.Tenant{ID: 2},
			total:  9999,
		},
		{
			name:   "配额为负视为无限制放行",
			tid:    2,
			tenant: domain.Tenant{ID: 2, MaxUserGroups: -1},
			total:  9999,
		},
		{
			name:   "未达配额放行",
			tid:    2,
			tenant: domain.Tenant{ID: 2, MaxUserGroups: 10},
			total:  9,
		},
		{
			name:    "组数恰好达到配额拒绝创建",
			tid:     2,
			tenant:  domain.Tenant{ID: 2, MaxUserGroups: 10},
			total:   10,
			wantErr: errs.ErrTenantQuotaExceeded,
		},
		{
			name:    "组数超过配额拒绝创建",
			tid:     2,
			tenant:  domain.Tenant{ID: 2, MaxUserGroups: 10},
			total:   15,
			wantErr: errs.ErrTenantQuotaExceeded,
		},
		{
			name:    "缺失租户上下文走 fail-closed",
			tid:     0,
			wantErr: errs.ErrMissingTenantContext,
		},
		{
			name:      "租户详情查询失败则创建失败不静默放行",
			tid:       2,
			tenantErr: errs.ErrRecordNotFound,
			wantErr:   errs.ErrRecordNotFound,
		},
		{
			name:    "组计数查询失败则创建失败不静默放行",
			tid:     2,
			tenant:  domain.Tenant{ID: 2, MaxUserGroups: 10},
			listErr: errs.ErrDatabaseError,
			wantErr: errs.ErrDatabaseError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				createCalled  bool
				listCalled    bool
				getByIdCalled bool
				listCtx       context.Context
			)
			repo := &quotaFakeRepo{
				listFn: func(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error) {
					listCalled = true
					listCtx = ctx
					// 计数只需 total，限定 limit=1 防止为校验拉取全量数据
					assert.Equal(t, int64(0), offset)
					assert.Equal(t, int64(1), limit)
					return nil, tc.total, tc.listErr
				},
				createFn: func(_ context.Context, _ domain.Group) (int64, error) {
					createCalled = true
					return 100, nil
				},
			}
			tenantSvc := &quotaFakeTenantSvc{getByIdFn: func(_ context.Context, id int64) (domain.Tenant, error) {
				getByIdCalled = true
				assert.Equal(t, tc.tid, id)
				return tc.tenant, tc.tenantErr
			}}
			svc := NewGroupService(repo, tenantSvc, nil, nil)

			ctx := ctxutil.WithTenantID(context.Background(), tc.tid)
			id, err := svc.Create(ctx, domain.Group{Name: "研发组", Code: "dev-group"})

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Zero(t, id)
				assert.False(t, createCalled, "拒绝路径不得触达仓储 Create")
			} else {
				require.NoError(t, err)
				assert.Equal(t, int64(100), id)
				assert.True(t, createCalled)
			}

			if listCalled {
				// 组计数透传同一 ctx，租户隔离由 gormx 插件按 ctx 租户过滤
				assert.Equal(t, ctx, listCtx)
			}

			// 租户查询仅在上下文有效时发生；组计数更进一步，仅发生在配额 > 0
			// 且租户详情读取成功的路径上（配额 0/负不产生计数查询）
			assert.Equal(t, tc.tid > 0, getByIdCalled, "租户详情查询时机不符合配额语义")
			wantCount := tc.tid > 0 && tc.tenantErr == nil && tc.tenant.MaxUserGroups > 0
			assert.Equal(t, wantCount, listCalled, "组计数查询时机不符合配额语义")
		})
	}
}

// TestGroupService_Update 验证更新失败时错误附带业务上下文向上传递。
func TestGroupService_Update(t *testing.T) {
	t.Run("更新成功", func(t *testing.T) {
		repo := &quotaFakeRepo{updateFn: func(_ context.Context, g domain.Group) (int64, error) {
			assert.Equal(t, int64(9), g.ID)
			return 1, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		require.NoError(t, svc.Update(context.Background(), domain.Group{ID: 9}))
	})

	t.Run("更新失败包装业务上下文", func(t *testing.T) {
		repo := &quotaFakeRepo{updateFn: func(_ context.Context, _ domain.Group) (int64, error) {
			return 0, errs.ErrDatabaseError
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		err := svc.Update(context.Background(), domain.Group{ID: 9})
		require.ErrorIs(t, err, errs.ErrDatabaseError)
		assert.Contains(t, err.Error(), "更新用户组失败")
	})
}

// TestGroupService_Delete 验证删除组时连带清理两类 Casbin 分组规则：
// 用户加入组的规则与组关联角色的规则。
func TestGroupService_Delete(t *testing.T) {
	tid := int64(7)
	ctx := ctxutil.WithTenantID(context.Background(), tid)

	t.Run("删除成功并清理两类分组规则", func(t *testing.T) {
		e := newQuotaEnforcer(t)
		// 预置同租户的两类规则与一条异租户规则（用于证明清理按租户隔离）
		_, err := e.AddGroupingPolicy(domain.UserSubject("alice"), domain.GroupSubject("dev"), "7")
		require.NoError(t, err)
		_, err = e.AddGroupingPolicy(domain.GroupSubject("dev"), domain.RoleSubject("admin"), "7")
		require.NoError(t, err)
		_, err = e.AddGroupingPolicy(domain.GroupSubject("dev"), domain.RoleSubject("viewer"), "8")
		require.NoError(t, err)

		// GetByID 返回的组编码须与种子规则一致，删除才具备清理目标
		repo := &quotaFakeRepo{getByIDFn: func(_ context.Context, id int64) (domain.Group, error) {
			return domain.Group{ID: id, Code: "dev"}, nil
		}}
		svc := NewGroupService(repo, nil, nil, e)
		require.NoError(t, svc.Delete(ctx, 9))

		// 用户->组 规则的组位于字段 1，组->角色 规则的组位于字段 0
		userRules, err := e.GetFilteredGroupingPolicy(1, domain.GroupSubject("dev"), "7")
		require.NoError(t, err)
		assert.Empty(t, userRules, "同租户的用户加组规则应被清理")
		roleRules, err := e.GetFilteredGroupingPolicy(0, domain.GroupSubject("dev"), "", "7")
		require.NoError(t, err)
		assert.Empty(t, roleRules, "同租户的组角色绑定规则应被清理")
		roleRules, err = e.GetFilteredGroupingPolicy(0, domain.GroupSubject("dev"), "", "8")
		require.NoError(t, err)
		assert.Len(t, roleRules, 1, "异租户规则不得被误清理")
	})

	t.Run("组详情查询失败包装业务上下文", func(t *testing.T) {
		repo := &quotaFakeRepo{getByIDFn: func(_ context.Context, _ int64) (domain.Group, error) {
			return domain.Group{}, errs.ErrRecordNotFound
		}}
		svc := NewGroupService(repo, nil, nil, newQuotaEnforcer(t))
		err := svc.Delete(ctx, 9)
		require.ErrorIs(t, err, errs.ErrRecordNotFound)
		assert.Contains(t, err.Error(), "查询用户组失败")
	})

	t.Run("删除失败包装业务上下文", func(t *testing.T) {
		repo := &quotaFakeRepo{deleteFn: func(_ context.Context, _ int64) error {
			return errs.ErrDatabaseError
		}}
		svc := NewGroupService(repo, nil, nil, newQuotaEnforcer(t))
		err := svc.Delete(ctx, 9)
		require.ErrorIs(t, err, errs.ErrDatabaseError)
		assert.Contains(t, err.Error(), "删除用户组失败")
	})
}

// TestGroupService_QueryPassthrough 验证纯查询方法对仓储返回值原样透传。
func TestGroupService_QueryPassthrough(t *testing.T) {
	t.Run("List 透传分页结果", func(t *testing.T) {
		want := []domain.Group{{ID: 1}, {ID: 2}}
		repo := &quotaFakeRepo{listFn: func(_ context.Context, offset, limit int64) ([]domain.Group, int64, error) {
			assert.Equal(t, int64(0), offset)
			assert.Equal(t, int64(20), limit)
			return want, 2, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		got, total, err := svc.List(context.Background(), 0, 20)
		require.NoError(t, err)
		assert.Equal(t, want, got)
		assert.Equal(t, int64(2), total)
	})

	t.Run("Search 透传模糊搜索结果", func(t *testing.T) {
		want := []domain.Group{{ID: 3}}
		repo := &quotaFakeRepo{searchFn: func(_ context.Context, keyword string, _, _ int64) ([]domain.Group, error) {
			assert.Equal(t, "dev", keyword)
			return want, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		got, err := svc.Search(context.Background(), "dev", 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("CountSearch 透传计数", func(t *testing.T) {
		repo := &quotaFakeRepo{countSearchFn: func(_ context.Context, keyword string) (int64, error) {
			assert.Equal(t, "dev", keyword)
			return 42, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		n, err := svc.CountSearch(context.Background(), "dev")
		require.NoError(t, err)
		assert.Equal(t, int64(42), n)
	})

	t.Run("GetByCode 透传组详情", func(t *testing.T) {
		repo := &quotaFakeRepo{getByCodeFn: func(_ context.Context, code string) (domain.Group, error) {
			return domain.Group{ID: 9, Code: code}, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		got, err := svc.GetByCode(context.Background(), "dev")
		require.NoError(t, err)
		assert.Equal(t, "dev", got.Code)
	})
}

// TestGroupService_AssignMembers 验证成员分配全链路：查组 -> 批量查用户 ->
// 落库绑定 -> Casbin 注册用户加组规则（含租户域），以及各失败分支不触达后续步骤。
func TestGroupService_AssignMembers(t *testing.T) {
	tid := int64(7)
	ctx := ctxutil.WithTenantID(context.Background(), tid)

	testCases := []struct {
		name        string
		usernames   []string
		userRepoErr error
		bindErr     error
		getCodeErr  error
		wantErr     error
	}{
		{name: "空用户列表直接返回不触达仓储", usernames: nil},
		{name: "分配成功", usernames: []string{"u1", "u2"}},
		{name: "组详情查询失败", usernames: []string{"u1"}, getCodeErr: errs.ErrRecordNotFound, wantErr: errs.ErrRecordNotFound},
		{name: "批量查用户失败", usernames: []string{"u1"}, userRepoErr: errs.ErrDatabaseError, wantErr: errs.ErrDatabaseError},
		{name: "落库绑定失败", usernames: []string{"u1"}, bindErr: errs.ErrDatabaseError, wantErr: errs.ErrDatabaseError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				bindCalled  bool
				bindUserIDs []int64
			)
			repo := &quotaFakeRepo{
				getByCodeFn: func(_ context.Context, code string) (domain.Group, error) {
					if tc.getCodeErr != nil {
						return domain.Group{}, tc.getCodeErr
					}
					return domain.Group{ID: 9, Code: code}, nil
				},
				bindMembersFn: func(_ context.Context, groupID int64, userIDs []int64) error {
					bindCalled = true
					assert.Equal(t, int64(9), groupID)
					bindUserIDs = userIDs
					return tc.bindErr
				},
			}
			userRepo := &quotaFakeUserRepo{findUsersByUsernamesFn: func(_ context.Context, usernames []string) ([]domain.User, error) {
				if tc.userRepoErr != nil {
					return nil, tc.userRepoErr
				}
				return []domain.User{{ID: 11, Username: usernames[0]}}, nil
			}}
			e := newQuotaEnforcer(t)
			svc := NewGroupService(repo, nil, userRepo, e)

			ok, err := svc.AssignMembers(ctx, "dev-group", tc.usernames)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, ok)
			if len(tc.usernames) == 0 {
				assert.False(t, bindCalled, "空列表不得触达绑定")
				return
			}
			assert.True(t, bindCalled)
			assert.Equal(t, []int64{11}, bindUserIDs)
			// Casbin 中应出现带租户域的加组规则
			rules, gerr := e.GetFilteredGroupingPolicy(0, domain.UserSubject("u1"), "", "7")
			require.NoError(t, gerr)
			assert.Len(t, rules, 1, "成员分配后应有用户加组规则")
		})
	}
}

// TestGroupService_RemoveMembers 验证移出成员同时解绑关系并注销 Casbin 规则。
func TestGroupService_RemoveMembers(t *testing.T) {
	tid := int64(7)
	ctx := ctxutil.WithTenantID(context.Background(), tid)

	t.Run("空用户列表直接返回", func(t *testing.T) {
		svc := NewGroupService(&quotaFakeRepo{}, nil, &quotaFakeUserRepo{}, newQuotaEnforcer(t))
		ok, err := svc.RemoveMembers(ctx, "dev-group", nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("移出成功并注销加组规则", func(t *testing.T) {
		var unbound []int64
		repo := &quotaFakeRepo{unbindMembersFn: func(_ context.Context, groupID int64, userIDs []int64) error {
			assert.Equal(t, int64(9), groupID)
			unbound = userIDs
			return nil
		}}
		userRepo := &quotaFakeUserRepo{findUsersByUsernamesFn: func(_ context.Context, _ []string) ([]domain.User, error) {
			return []domain.User{{ID: 11, Username: "u1"}}, nil
		}}
		e := newQuotaEnforcer(t)
		_, err := e.AddGroupingPolicy(domain.UserSubject("u1"), domain.GroupSubject("dev-group"), "7")
		require.NoError(t, err)

		svc := NewGroupService(repo, nil, userRepo, e)
		ok, err := svc.RemoveMembers(ctx, "dev-group", []string{"u1"})
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []int64{11}, unbound)
		rules, gerr := e.GetFilteredGroupingPolicy(0, domain.UserSubject("u1"), "", "7")
		require.NoError(t, gerr)
		assert.Empty(t, rules, "移出成员后加组规则应被注销")
	})
}

// TestGroupService_ListMembers 验证先按组编码定位组再透传成员分页查询。
func TestGroupService_ListMembers(t *testing.T) {
	ctx := context.Background()
	t.Run("成员列表透传", func(t *testing.T) {
		var gotGroupID int64
		repo := &quotaFakeRepo{listMembersFn: func(_ context.Context, groupID int64, _, _ int64, _ string) ([]domain.User, int64, error) {
			gotGroupID = groupID
			return []domain.User{{ID: 11}}, 1, nil
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		users, total, err := svc.ListMembers(ctx, "dev-group", 0, 10, "")
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, int64(9), gotGroupID, "应使用组编码解析出的组 ID")
	})

	t.Run("组详情查询失败包装业务上下文", func(t *testing.T) {
		repo := &quotaFakeRepo{getByCodeFn: func(_ context.Context, _ string) (domain.Group, error) {
			return domain.Group{}, errs.ErrRecordNotFound
		}}
		svc := NewGroupService(repo, nil, nil, nil)
		_, _, err := svc.ListMembers(ctx, "dev-group", 0, 10, "")
		require.ErrorIs(t, err, errs.ErrRecordNotFound)
	})
}

// TestGroupService_ListAttachedGroupsByUser 验证按用户 ID 或用户名两种
// 入参形式解析归属组列表，以及双空入参直接短路返回。
func TestGroupService_ListAttachedGroupsByUser(t *testing.T) {
	ctx := context.Background()

	t.Run("双空入参直接返回空", func(t *testing.T) {
		svc := NewGroupService(&quotaFakeRepo{}, nil, &quotaFakeUserRepo{}, nil)
		groups, total, err := svc.ListAttachedGroupsByUser(ctx, "", 0, 0, 10, "")
		require.NoError(t, err)
		assert.Nil(t, groups)
		assert.Zero(t, total)
	})

	t.Run("按用户 ID 直查", func(t *testing.T) {
		var gotUserID int64
		repo := &quotaFakeRepo{listGroupsByUserIDFn: func(_ context.Context, userID int64, _, _ int64, _ string) ([]domain.Group, int64, error) {
			gotUserID = userID
			return []domain.Group{{ID: 9}}, 1, nil
		}}
		svc := NewGroupService(repo, nil, &quotaFakeUserRepo{}, nil)
		groups, total, err := svc.ListAttachedGroupsByUser(ctx, "", 11, 0, 10, "")
		require.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, int64(11), gotUserID)
	})

	t.Run("仅用户名时先解析用户", func(t *testing.T) {
		var gotUserID int64
		repo := &quotaFakeRepo{listGroupsByUserIDFn: func(_ context.Context, userID int64, _, _ int64, _ string) ([]domain.Group, int64, error) {
			gotUserID = userID
			return nil, 0, nil
		}}
		userRepo := &quotaFakeUserRepo{findByUsernameFn: func(_ context.Context, username string) (domain.User, error) {
			assert.Equal(t, "alice", username)
			return domain.User{ID: 11, Username: username}, nil
		}}
		svc := NewGroupService(repo, nil, userRepo, nil)
		_, _, err := svc.ListAttachedGroupsByUser(ctx, "alice", 0, 0, 10, "")
		require.NoError(t, err)
		assert.Equal(t, int64(11), gotUserID)
	})
}

// TestGroupService_ListAttachedGroupsByRole 验证按角色反查附属组：
// 从 Casbin 分组规则提取组编码后转交仓储查询。
func TestGroupService_ListAttachedGroupsByRole(t *testing.T) {
	ctx := ctxutil.WithTenantID(context.Background(), 7)

	t.Run("空角色编码直接返回空", func(t *testing.T) {
		svc := NewGroupService(&quotaFakeRepo{}, nil, nil, newQuotaEnforcer(t))
		groups, total, err := svc.ListAttachedGroupsByRole(ctx, "", 0, 10, "")
		require.NoError(t, err)
		assert.Nil(t, groups)
		assert.Zero(t, total)
	})

	t.Run("从分组规则提取组编码并查询", func(t *testing.T) {
		e := newQuotaEnforcer(t)
		_, err := e.AddGroupingPolicy(domain.GroupSubject("dev"), domain.RoleSubject("admin"), "7")
		require.NoError(t, err)

		var gotCodes []string
		repo := &quotaFakeRepo{listGroupsByCodesFn: func(_ context.Context, codes []string, _, _ int64, _ string) ([]domain.Group, int64, error) {
			gotCodes = codes
			return []domain.Group{{ID: 9, Code: codes[0]}}, 1, nil
		}}
		svc := NewGroupService(repo, nil, nil, e)
		groups, total, err := svc.ListAttachedGroupsByRole(ctx, "admin", 0, 10, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"dev"}, gotCodes, "应提取组编码而非完整 subject")
		assert.Len(t, groups, 1)
		assert.Equal(t, int64(1), total)
	})

	t.Run("无分组规则时返回空", func(t *testing.T) {
		var listCalled bool
		repo := &quotaFakeRepo{listGroupsByCodesFn: func(_ context.Context, _ []string, _, _ int64, _ string) ([]domain.Group, int64, error) {
			listCalled = true
			return nil, 0, nil
		}}
		svc := NewGroupService(repo, nil, nil, newQuotaEnforcer(t))
		groups, _, err := svc.ListAttachedGroupsByRole(ctx, "admin", 0, 10, "")
		require.NoError(t, err)
		assert.Nil(t, groups)
		assert.False(t, listCalled, "无规则时不得触达仓储查询")
	})
}

// TestGroupService_AssignAndListRemoveRole 验证组-角色授权的生命周期：
// 授权后可列举角色，解除授权后列举为空。
func TestGroupService_AssignAndListRemoveRole(t *testing.T) {
	ctx := ctxutil.WithTenantID(context.Background(), 7)
	e := newQuotaEnforcer(t)
	svc := NewGroupService(&quotaFakeRepo{}, nil, nil, e)

	ok, err := svc.AssignRole(ctx, "dev", "admin")
	require.NoError(t, err)
	assert.True(t, ok)

	roles, err := svc.ListRoles(ctx, "dev")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, roles, "授权后应能列举到角色")

	ok, err = svc.RemoveRole(ctx, "dev", "admin")
	require.NoError(t, err)
	assert.True(t, ok)

	roles, err = svc.ListRoles(ctx, "dev")
	require.NoError(t, err)
	assert.Empty(t, roles, "解除授权后不应再列举到角色")
}
