package user

import (
	"context"
	"errors"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	repomocks "github.com/Havens-blog/e-iam/internal/repository/mocks"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	tenantmocks "github.com/Havens-blog/e-iam/internal/service/tenant/mocks"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func TestUserService_ValidatePassword(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "默认规则 - 长度不足8位拒绝",
			password: "short",
			wantErr:  errs.ErrPasswordWeak,
		},
		{
			name:     "默认规则 - 满足8位通过",
			password: "password123",
			wantErr:  nil,
		},
	}

	svc := &userService{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validatePassword(context.Background(), tc.password)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_List(t *testing.T) {
	mockUsers := []domain.User{
		{ID: 1, Username: "user1"},
		{ID: 2, Username: "user2"},
	}

	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) repository.IUserRepository
		offset    int64
		limit     int64
		keyword   string
		wantUsers []domain.User
		wantTotal int64
		wantErr   error
	}{
		{
			name: "并发查询列表与总数成功",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().List(gomock.Any(), int64(0), int64(10), "user").Return(mockUsers, nil)
				repo.EXPECT().Count(gomock.Any(), "user").Return(int64(2), nil)
				return repo
			},
			offset:    0,
			limit:     10,
			keyword:   "user",
			wantUsers: mockUsers,
			wantTotal: 2,
			wantErr:   nil,
		},
		{
			name: "查询列表失败触发联动取消并返回错误",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().List(gomock.Any(), int64(0), int64(10), "").Return(nil, errors.New("db error"))
				repo.EXPECT().Count(gomock.Any(), "").Return(int64(0), nil).AnyTimes()
				return repo
			},
			offset:  0,
			limit:   10,
			keyword: "",
			wantErr: errors.New("db error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := tc.mock(ctrl)
			svc := NewUserService(repo, nil, nil, nil)

			users, total, err := svc.List(context.Background(), tc.offset, tc.limit, tc.keyword)
			if tc.wantErr != nil {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantUsers, users)
			assert.Equal(t, tc.wantTotal, total)
		})
	}
}

func TestUserService_SwitchTenant(t *testing.T) {
	testCases := []struct {
		name           string
		mock           func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService)
		uid            int64
		targetTenantID int64
		wantErr        error
	}{
		{
			name: "拥有目标租户访问权",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(true, nil)
				userRepo.EXPECT().UpdateLastActiveTenantID(gomock.Any(), int64(100), int64(10)).Return(nil)
				return userRepo, tenantSvc
			},
			uid:            100,
			targetTenantID: 10,
			wantErr:        nil,
		},
		{
			name: "无目标租户访问权拦截",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(false, nil)
				return userRepo, tenantSvc
			},
			uid:            100,
			targetTenantID: 20,
			wantErr:        errs.ErrTenantAccessDenied,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo, tenantSvc := tc.mock(ctrl)
			svc := NewUserService(userRepo, tenantSvc, nil, nil)

			err := svc.SwitchTenant(context.Background(), tc.uid, tc.targetTenantID)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_Signup(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService)
		user    domain.User
		wantID  int64
		wantErr error
	}{
		{
			name: "用户名已存在",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().FindByUsername(gomock.Any(), "existing_user").Return(domain.User{ID: 1}, nil)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				// 配额未设(0)视为无限制，专注验证原有查重语义不受配额改造影响
				tenantSvc.EXPECT().GetByID(gomock.Any(), int64(2)).Return(domain.Tenant{ID: 2}, nil)
				return repo, tenantSvc
			},
			user: domain.User{
				Username: "existing_user",
				Password: "Password123!",
			},
			wantErr: errs.ErrUserExist,
		},
		{
			name: "密码合规创建成功并加密存储",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().FindByUsername(gomock.Any(), "new_user").Return(domain.User{}, errors.New("not found"))
				repo.EXPECT().Create(gomock.Any(), gomock.Cond(func(x any) bool {
					u, ok := x.(domain.User)
					if !ok {
						return false
					}
					// 验证入库密码已完成 bcrypt 加盐加密，非明文
					err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("ValidPassword123"))
					return err == nil && u.Source == domain.SourceLocal && u.Status == domain.StatusActive
				})).Return(int64(999), nil)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				tenantSvc.EXPECT().GetByID(gomock.Any(), int64(2)).Return(domain.Tenant{ID: 2}, nil)
				return repo, tenantSvc
			},
			user: domain.User{
				Username: "new_user",
				Password: "ValidPassword123",
			},
			wantID:  999,
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, tenantSvc := tc.mock(ctrl)
			svc := NewUserService(repo, tenantSvc, nil, nil)

			// Signup 已是配额强制校验入口，须携带有效租户上下文；配额放行/拦截
			// 语义由 TestUserService_SignupQuotaEnforcement 专项覆盖
			ctx := ctxutil.WithTenantID(context.Background(), 2)
			id, err := svc.Signup(ctx, tc.user)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantID, id)
			}
		})
	}
}

// TestUserService_SignupQuotaEnforcement 验证 Signup 落库创建用户前的租户 MaxUsers
// 配额强制校验（tenant-management 规格 R2.5）：仅当 MaxUsers > 0 且当前租户成员
// 数已达上限时拒绝并返回 ErrTenantQuotaExceeded；配额 0/负数视为无限制直接放行
// 且不产生计数查询；缺失租户上下文走 fail-closed；租户查询/计数失败透传错误
// 不静默放行；配额通过后原有查重、验密码、Create 流程保持不变。
func TestUserService_SignupQuotaEnforcement(t *testing.T) {
	testCases := []struct {
		name      string
		tid       int64
		tenant    domain.Tenant
		tenantErr error
		total     int64
		countErr  error
		username  string
		wantErr   error
	}{
		{
			name:     "配额未设(0)视为无限制放行",
			tid:      2,
			tenant:   domain.Tenant{ID: 2},
			total:    9999,
			username: "new_user",
		},
		{
			name:     "配额为负视为无限制放行",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: -1},
			total:    9999,
			username: "new_user",
		},
		{
			name:     "未达配额放行",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: 10},
			total:    9,
			username: "new_user",
		},
		{
			name:     "用户数恰好达到配额拒绝创建",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: 10},
			total:    10,
			username: "new_user",
			wantErr:  errs.ErrTenantQuotaExceeded,
		},
		{
			name:     "用户数超过配额拒绝创建",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: 10},
			total:    15,
			username: "new_user",
			wantErr:  errs.ErrTenantQuotaExceeded,
		},
		{
			name:     "缺失租户上下文走 fail-closed",
			tid:      0,
			username: "new_user",
			wantErr:  errs.ErrMissingTenantContext,
		},
		{
			name:      "租户详情查询失败则创建失败不静默放行",
			tid:       2,
			tenantErr: errs.ErrRecordNotFound,
			username:  "new_user",
			wantErr:   errs.ErrRecordNotFound,
		},
		{
			name:     "用户计数查询失败则创建失败不静默放行",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: 10},
			countErr: errs.ErrDatabaseError,
			username: "new_user",
			wantErr:  errs.ErrDatabaseError,
		},
		{
			name:     "配额通过后原有查重流程保持不变",
			tid:      2,
			tenant:   domain.Tenant{ID: 2, MaxUsers: 10},
			total:    9,
			username: "existing_user",
			wantErr:  errs.ErrUserExist,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			var countCalled bool
			repo := repomocks.NewMockIUserRepository(ctrl)
			tenantSvc := tenantmocks.NewMockITenantService(ctrl)

			// 租户详情仅在上下文有效时读取；gomock 严格模式下未注册的调用即测试失败，
			// 天然证明 fail-closed 路径不触达任何租户/仓储操作
			if tc.tid > 0 {
				tenantSvc.EXPECT().GetByID(gomock.Any(), tc.tid).Return(tc.tenant, tc.tenantErr)
			}
			// 用户计数仅在配额 > 0 且租户详情读取成功时发生；CountSearch 经
			// membershipScope 强制按当前租户成员过滤，保证计数不跨租户
			needCount := tc.tid > 0 && tc.tenantErr == nil && tc.tenant.MaxUsers > 0
			if needCount {
				repo.EXPECT().CountSearch(gomock.Any(), "").DoAndReturn(
					func(_ context.Context, _ string) (int64, error) {
						countCalled = true
						return tc.total, tc.countErr
					})
			}
			switch {
			case tc.wantErr == nil:
				repo.EXPECT().FindByUsername(gomock.Any(), tc.username).Return(domain.User{}, errors.New("not found"))
				repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(int64(999), nil)
			case errors.Is(tc.wantErr, errs.ErrUserExist):
				repo.EXPECT().FindByUsername(gomock.Any(), tc.username).Return(domain.User{ID: 1}, nil)
			}

			svc := NewUserService(repo, tenantSvc, nil, nil)

			ctx := ctxutil.WithTenantID(context.Background(), tc.tid)
			id, err := svc.Signup(ctx, domain.User{Username: tc.username, Password: "ValidPassword123"})

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Zero(t, id)
			} else {
				require.NoError(t, err)
				assert.Equal(t, int64(999), id)
			}
			assert.Equal(t, needCount, countCalled, "用户计数查询时机不符合配额语义")
		})
	}
}
