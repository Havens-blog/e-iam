package user

import (
	"context"
	"fmt"
	"unicode"

	"github.com/Havens-blog/e-iam/internal/cryptox"
	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	idsource "github.com/Havens-blog/e-iam/internal/service/identity_source"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

type IUserService interface {
	Signup(ctx context.Context, u domain.User) (int64, error)

	// GetById 根据 ID 获取用户信息
	GetById(ctx context.Context, id int64) (domain.User, error)

	// GetByIDs 根据 IDS 获取用户列表
	GetByIDs(ctx context.Context, ids []int64) ([]domain.User, error)

	// GetByUsername 根据用户名获取用户信息
	GetByUsername(ctx context.Context, username string) (domain.User, error)

	// GetByUsernames 根据用户名获取用户信息
	GetByUsernames(ctx context.Context, usernames []string) ([]domain.User, error)

	// SwitchTenant 切换当前激活的租户空间
	SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) error
	// SetDefaultTenant 设置用户默认登录租户（个人偏好，switch 不覆盖；下次登录直接落入）
	SetDefaultTenant(ctx context.Context, uid int64, tenantID int64) error
	// Invite 邀请用户进入系统
	Invite(ctx context.Context, username string) error

	// List 分页获取用户列表，支持模糊搜索
	List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// Search 全量搜索用户
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountSearch 根据关键词获取符合条件的用户总数
	CountSearch(ctx context.Context, keyword string) (int64, error)
	// Update 更新用户基本资料 (Profile)
	Update(ctx context.Context, u domain.User) (int64, error)
	// UpdatePassword 修改用户本地密码
	UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error
	// BatchDelete 批量删除用户
	BatchDelete(ctx context.Context, ids []int64) (int64, error)

	// CheckUsersExist 批量检查用户名是否存在
	CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error)
	// GetAttachedUsersWithFilter 获取关联角色的用户详情，支持关键词过滤
	GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// BindIdentity 手动绑定外部身份
	BindIdentity(ctx context.Context, uid int64, identity domain.UserIdentity) error
	// UnbindIdentity 解除外部身份绑定
	UnbindIdentity(ctx context.Context, userID int64, provider, identityID string) error
	// ListIdentitiesByUserID 获取用户的身份绑定列表
	ListIdentitiesByUserID(ctx context.Context, userID int64, provider string) ([]domain.UserIdentity, error)
	// ManageIdentities 批量治理/管理用户的外部身份绑定关系
	ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error
	// GenerateBindToken 生成临时绑定令牌并存入缓存
	GenerateBindToken(ctx context.Context, ident domain.OidcIdentity) (string, error)
	// ConsumeBindToken 消费令牌并执行绑定
	ConsumeBindToken(ctx context.Context, uid int64, token string) error

	SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error
	GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error)

	// GenerateTOTPSetup 生成 TOTP 密钥和二维码
	GenerateTOTPSetup(ctx context.Context, userID int64) (string, string, error)
	// VerifyAndEnableTOTP 验证并开启 TOTP MFA
	VerifyAndEnableTOTP(ctx context.Context, userID int64, code, secret string) error
	// DisableMFA 关闭 MFA
	DisableMFA(ctx context.Context, userID int64) error
}

var (
	ErrMfaAttemptsExhausted = errs.ErrMfaAttemptsExhausted
	ErrMfaTokenNotFound     = errs.ErrMfaTokenNotFound
)

type userService struct {
	repo      repository.IUserRepository
	tenantSvc tenant.ITenantService
	idsSvc    idsource.IService
	cm        *cryptox.CryptoManager
}

func (s *userService) GetByUsernames(ctx context.Context, usernames []string) ([]domain.User, error) {
	return s.repo.FindByUsernames(ctx, usernames)
}

func (s *userService) GetByIDs(ctx context.Context, ids []int64) ([]domain.User, error) {
	return s.repo.FindByIds(ctx, ids)
}

func NewUserService(r repository.IUserRepository, tenantSvc tenant.ITenantService,
	idsSvc idsource.IService, cm *cryptox.CryptoManager) IUserService {
	return &userService{
		repo:      r,
		tenantSvc: tenantSvc,
		idsSvc:    idsSvc,
		cm:        cm,
	}
}

func (s *userService) SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) error {
	// 直接复用 CheckUserTenantAccess 校验 Membership 合约是否存在
	targetCtx := ctxutil.WithTenantID(ctx, targetTenantID)
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(targetCtx, uid)
	if err != nil {
		return err
	}

	if !hasAccess {
		return errs.ErrTenantAccessDenied
	}

	// 记录用户最近一次活跃租户，供后续登录免选直达
	_ = s.repo.UpdateLastActiveTenantID(ctx, uid, targetTenantID)

	return nil
}

// SetDefaultTenant 设置用户默认登录租户。
// 与 SwitchTenant 的区别：本方法只持久化「默认登录租户」偏好，不改写 LastActiveTenantID，
// 也不切换当前会话——下次登录时 resolveActiveTenant 会优先采用本字段。
// 校验目标租户确属该用户（Membership 存在），防越权设他人租户为默认。
func (s *userService) SetDefaultTenant(ctx context.Context, uid int64, tenantID int64) error {
	targetCtx := ctxutil.WithTenantID(ctx, tenantID)
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(targetCtx, uid)
	if err != nil {
		return err
	}
	if !hasAccess {
		return errs.ErrTenantAccessDenied
	}

	return s.repo.UpdateDefaultTenantID(ctx, uid, tenantID)
}

func (s *userService) Invite(ctx context.Context, username string) error {
	// 1. 全局查找用户（UserRepository 的 FindByUsername 已经是全局的了，因为它不依赖租户插件）
	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("查找用户失败: %w", err)
	}

	// 2. 建立该用户与当前操作租户的 Membership 关系
	return s.tenantSvc.AssignUser(ctx, u.ID)
}

func (s *userService) ListIdentitiesByUserID(ctx context.Context, userID int64, provider string) ([]domain.UserIdentity, error) {
	return s.repo.FindIdentitiesByUserID(ctx, userID, provider)
}

func (s *userService) Signup(ctx context.Context, u domain.User) (int64, error) {
	// 配额校验 (R2.5)：Signup 是唯一用户创建入口（覆盖自注册 /signup 与管理员 /create
	// 两条 web 路由）。写操作防缺失租户上下文，与 R2.6 组配额同模式形成纵深防御——
	// gormx 插件负责数据行过滤，这里显式业务拒绝，避免 tid<=0 时配额读取与
	// 用户计数被静默绕过
	tid := ctxutil.GetTenantID(ctx).Int64()
	if tid <= 0 {
		return 0, errs.ErrMissingTenantContext
	}

	// MaxUsers <= 0 视为无限制，只有 > 0 才计数拦截；CountSearch 经 DAO 层
	// membershipScope 强制按当前租户成员过滤，保证计数不跨租户
	t, err := s.tenantSvc.GetByID(ctx, tid)
	if err != nil {
		return 0, fmt.Errorf("查询租户配额失败: %w", err)
	}
	if quota := t.MaxUsers; quota > 0 {
		total, err := s.repo.CountSearch(ctx, "")
		if err != nil {
			return 0, fmt.Errorf("统计用户数量失败: %w", err)
		}
		if total >= quota {
			return 0, errs.ErrTenantQuotaExceeded
		}
	}

	_, err = s.repo.FindByUsername(ctx, u.Username)
	if err == nil {
		return 0, errs.ErrUserExist
	}

	if u.Source == "" {
		u.Source = domain.SourceLocal
	}

	if u.Status == domain.StatusUnknown {
		u.Status = domain.StatusActive
	}

	if u.Password != "" {
		if err = s.validatePassword(ctx, u.Password); err != nil {
			return 0, err
		}

		hash, err1 := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err1 != nil {
			return 0, err1
		}
		u.Password = string(hash)
	}
	return s.repo.Create(ctx, u)
}

func (s *userService) UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error {
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return fmt.Errorf("查找用户失败: %w", err)
	}

	// 校验旧密码
	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(oldPassword)); err != nil {
		return errs.ErrInvalidUser
	}

	// 校验新密码复杂度
	if err = s.validatePassword(ctx, newPassword); err != nil {
		return err
	}

	// 加密新密码
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hash)
	_, err = s.repo.Update(ctx, u)
	if err != nil {
		return fmt.Errorf("更新用户密码失败: %w", err)
	}
	return nil
}

func (s *userService) GetById(ctx context.Context, id int64) (domain.User, error) {
	return s.repo.FindById(ctx, id)
}

func (s *userService) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.repo.FindByUsername(ctx, username)
}

func (s *userService) List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	var (
		users []domain.User
		total int64
	)
	eg, gctx := errgroup.WithContext(ctx)

	// 1. 并发查询用户列表
	eg.Go(func() error {
		var err error
		users, err = s.repo.List(gctx, offset, limit, keyword)
		if err != nil {
			return fmt.Errorf("查询用户列表失败: %w", err)
		}
		return nil
	})

	// 2. 并发查询总数
	eg.Go(func() error {
		var err error
		total, err = s.repo.Count(gctx, keyword)
		if err != nil {
			return fmt.Errorf("查询用户总数失败: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (s *userService) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
	if limit <= 0 {
		return []domain.User{}, nil
	}
	return s.repo.Search(ctx, keyword, offset, limit)
}

func (s *userService) CountSearch(ctx context.Context, keyword string) (int64, error) {
	return s.repo.CountSearch(ctx, keyword)
}

// requireTenantMembership 写操作防跨租户接管：目标用户必须是当前上下文租户的成员。
// 与 gormx 租户插件形成纵深防御：插件负责数据行过滤，本校验负责显式业务语义拒绝。
func (s *userService) requireTenantMembership(ctx context.Context, uid int64) error {
	if ctxutil.GetTenantID(ctx) <= 0 {
		return errs.ErrMissingTenantContext
	}
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(ctx, uid)
	if err != nil {
		return err
	}
	if !hasAccess {
		return errs.ErrTenantAccessDenied
	}
	return nil
}

func (s *userService) Update(ctx context.Context, u domain.User) (int64, error) {
	if err := s.requireTenantMembership(ctx, u.ID); err != nil {
		return 0, err
	}
	return s.repo.Update(ctx, u)
}

func (s *userService) Delete(ctx context.Context, id int64) error {
	if err := s.requireTenantMembership(ctx, id); err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}

func (s *userService) BatchDelete(ctx context.Context, ids []int64) (int64, error) {
	for _, id := range ids {
		if err := s.requireTenantMembership(ctx, id); err != nil {
			return 0, err
		}
	}
	return s.repo.BatchDelete(ctx, ids)
}

func (s *userService) CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error) {
	return s.repo.CheckUsersExist(ctx, usernames)
}

func (s *userService) GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	return s.repo.GetAttachedUsersWithFilter(ctx, roleCode, offset, limit, keyword)
}

func (s *userService) BindIdentity(ctx context.Context, uid int64, identity domain.UserIdentity) error {
	// P1-5 防跨租户身份接管：绑定目标必须是当前租户成员
	if err := s.requireTenantMembership(ctx, uid); err != nil {
		return err
	}
	identity.UserID = uid
	return s.repo.SaveIdentity(ctx, identity)
}

func (s *userService) UnbindIdentity(ctx context.Context, userID int64, provider, identityID string) error {
	if err := s.requireTenantMembership(ctx, userID); err != nil {
		return err
	}
	return s.repo.DeleteIdentity(ctx, userID, provider, identityID)
}

func (s *userService) ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error {
	if err := s.requireTenantMembership(ctx, uid); err != nil {
		return err
	}
	for _, id := range identities {
		id.UserID = uid
		// 策略：如果标识为空，则解绑；否则绑定/更新
		if id.IdentityKey() == "" {
			if err := s.repo.DeleteIdentity(ctx, uid, id.Provider, id.IdentityKey()); err != nil {
				return fmt.Errorf("解绑身份失败: %w", err)
			}
		} else {
			if err := s.repo.SaveIdentity(ctx, id); err != nil {
				return fmt.Errorf("绑定身份失败: %w", err)
			}
		}
	}
	return nil
}

func (s *userService) validatePassword(ctx context.Context, password string) error {
	// 1. 获取本地口令策略（复用统一方法）
	localCfg, found := s.getLocalConfig(ctx)

	// 2. 如果没配置，执行默认最低要求：8 位
	if !found {
		if len(password) < 8 {
			return errs.ErrPasswordWeak
		}
		return nil
	}

	// 3. 密码复杂度校验
	if len(password) < localCfg.MinLength {
		return errs.ErrPasswordWeak
	}

	var hasDigit, hasUpper, hasLower, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	if (localCfg.RequireDigit && !hasDigit) ||
		(localCfg.RequireUpper && !hasUpper) ||
		(localCfg.RequireLower && !hasLower) ||
		(localCfg.RequireSymbol && !hasSymbol) {
		return errs.ErrPasswordWeak
	}

	return nil
}

// getLocalConfig 获取已启用的本地口令策略配置
// NOTE: 抽取为独立方法，避免 loginLocal 和 validatePassword 重复查全量身份源列表
func (s *userService) getLocalConfig(ctx context.Context) (domain.LocalConfig, bool) {
	if s.idsSvc == nil {
		return domain.LocalConfig{}, false
	}
	source, err := s.idsSvc.FindEnabled(ctx, domain.LOCAL)
	if err != nil {
		return domain.LocalConfig{}, false
	}

	return source.LocalConfig, true
}

func (s *userService) GenerateBindToken(ctx context.Context, ident domain.OidcIdentity) (string, error) {
	token := uuid.New().String()
	if err := s.repo.SetBindState(ctx, token, ident); err != nil {
		return "", fmt.Errorf("保存绑定令牌失败: %w", err)
	}
	return token, nil
}

func (s *userService) ConsumeBindToken(ctx context.Context, uid int64, token string) error {
	ident, err := s.repo.GetBindState(ctx, token)
	if err != nil {
		return fmt.Errorf("读取绑定令牌失败: %w", err)
	}

	// 登录期绑定是“已通过本地口令认证”的显式确认路径：此时会话尚未颁发、
	// 上下文无租户信息，故不经 BindIdentity 的成员校验，直接落库（uid 服务端可信）
	identity := domain.UserIdentity{
		Provider:   ident.Provider,
		IdentityID: ident.ExternalID,
	}
	identity.UserID = uid
	return s.repo.SaveIdentity(ctx, identity)
}
