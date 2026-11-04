package tenant

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	permmocks "github.com/Havens-blog/e-iam/internal/service/permission/mocks"
	tenantmocks "github.com/Havens-blog/e-iam/internal/service/tenant/mocks"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/ecodeclub/ekit"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// configFakeSession 是 session.Session 的最小测试替身（本文件自包含，独立命名
// 避免与其他测试文件冲突）。
type configFakeSession struct {
	claims session.Claims
}

func (s *configFakeSession) Set(ctx context.Context, key string, val any) error { return nil }
func (s *configFakeSession) Get(ctx context.Context, key string) ekit.AnyValue {
	return ekit.AnyValue{Val: ""}
}
func (s *configFakeSession) Del(ctx context.Context, key string) error { return nil }
func (s *configFakeSession) Destroy(ctx context.Context) error         { return nil }
func (s *configFakeSession) Claims() session.Claims                    { return s.claims }

var _ session.Session = (*configFakeSession)(nil)

// newConfigGinxContext 构造携带租户上下文的 ginx.Context，开启
// ContextWithFallback 使 ctxutil 键值可透传。
func newConfigGinxContext(tenantID int64, params gin.Params) *ginx.Context {
	gin.SetMode(gin.TestMode)
	ginCtx, engine := gin.CreateTestContext(httptest.NewRecorder())
	engine.ContextWithFallback = true
	c := ctxutil.WithOriginTenantID(ctxutil.WithTenantID(context.Background(), tenantID), tenantID)
	req := httptest.NewRequest("POST", "/api/tenant/test", nil)
	req = req.WithContext(c)
	ginCtx.Request = req
	ginCtx.Params = params
	return &ginx.Context{Context: ginCtx}
}

// TestToTenantVO_ConfigFields 验证 VO 映射不丢三类配置字段。
func TestToTenantVO_ConfigFields(t *testing.T) {
	src := domain.Tenant{
		ID:             1,
		Name:           "Acme",
		Code:           "acme",
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  map[string]bool{"cdn": true, "waf": false},
		AllowedVendors: []string{"aliyun", "tencent"},
	}
	got := ToTenantVO(src)
	assert.Equal(t, src.MaxAccounts, got.MaxAccounts)
	assert.Equal(t, src.MaxUsers, got.MaxUsers)
	assert.Equal(t, src.MaxUserGroups, got.MaxUserGroups)
	assert.Equal(t, src.FeatureSwitch, got.FeatureSwitch)
	assert.Equal(t, src.AllowedVendors, got.AllowedVendors)

	// JSON 契约断言：配置字段以 snake_case 键出现在响应体中，
	// 保证前端可按契约键读取（键名漂移是契约级破坏）
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	for _, key := range []string{"max_accounts", "max_users", "max_user_groups", "feature_switch", "allowed_vendors"} {
		assert.Contains(t, m, key)
	}
}

// TestHandler_CreateTenant_ConfigPassthrough 验证 HTTP 创建入口把三类配置
// 从请求体完整透传至 Service 层。
func TestHandler_CreateTenant_ConfigPassthrough(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	req := CreateTenantReq{
		Name: "Acme", Code: "acme",
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  map[string]bool{"cdn": true},
		AllowedVendors: []string{"aliyun"},
	}
	svc := tenantmocks.NewMockITenantService(ctrl)
	svc.EXPECT().CreateTenant(gomock.Any(), domain.Tenant{
		Name: "Acme", Code: "acme",
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  req.FeatureSwitch,
		AllowedVendors: req.AllowedVendors,
	}, "alice", int64(42)).Return(int64(7), nil)

	permSvc := permmocks.NewMockIPermissionService(ctrl)
	permSvc.EXPECT().AssignRoleToUser(gomock.Any(), "alice", "admin").Return(true, nil)

	h := NewHandler(svc, permSvc)
	sess := &configFakeSession{claims: session.Claims{Uid: 42, Data: map[string]string{"username": "alice"}}}
	res, err := h.CreateTenant(newConfigGinxContext(0, nil), req, sess)
	require.NoError(t, err)
	assert.Equal(t, int64(7), res.Data)
}

// TestHandler_UpdateTenant_ConfigPassthrough 验证 HTTP 更新入口把三类配置
// 从请求体完整透传至 Service 层。
func TestHandler_UpdateTenant_ConfigPassthrough(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	svc := tenantmocks.NewMockITenantService(ctrl)
	svc.EXPECT().Update(gomock.Any(), domain.Tenant{
		ID: 5, Name: "New", Code: "new", Domain: "d", Status: 2,
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  map[string]bool{"waf": true},
		AllowedVendors: []string{"aws"},
	}).Return(nil)

	h := NewHandler(svc, nil)
	res, err := h.UpdateTenant(newConfigGinxContext(ctxutil.SystemTenantID, nil), UpdateTenantReq{
		ID: 5, Name: "New", Code: "new", Domain: "d", Status: 2,
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  map[string]bool{"waf": true},
		AllowedVendors: []string{"aws"},
	})
	require.NoError(t, err)
	assert.Zero(t, res.Code)
}
