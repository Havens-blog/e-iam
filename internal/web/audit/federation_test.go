package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	repomocks "github.com/Havens-blog/e-iam/internal/repository/mocks"
	auditsvc "github.com/Havens-blog/e-iam/internal/service/audit"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// fedFixture 测试环境：真 gin engine（与 ioc/web.go 相同的 S2S 组注册方式，
// 不含 S2STokenAuth——验签由 CI 集成覆盖，单测聚焦 fail-closed 闸门与租户注入）
type fedFixture struct {
	ctrl   *gomock.Controller
	repo   *repomocks.MockIAuditRepository
	engine *gin.Engine
}

func newFedFixture(t *testing.T, enabled bool, allowed []int) *fedFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	repo := repomocks.NewMockIAuditRepository(ctrl)
	viper.Set("audit.federation.enabled", enabled)
	viper.Set("audit.federation.allowed_tenants", allowed)

	h := &Handler{svc: auditsvc.NewService(repo)}
	engine := gin.New()
	g := engine.Group("/api/s2s")
	g.GET("/audit/events", ginx.W(h.FederationEvents))

	t.Cleanup(func() {
		ctrl.Finish()
		viper.Set("audit.federation.enabled", false)
		viper.Set("audit.federation.allowed_tenants", []int{})
	})
	return &fedFixture{ctrl: ctrl, repo: repo, engine: engine}
}

// do 发起请求并返回 HTTP 状态码、响应体；同时捕获到达仓储层的租户上下文
func (f *fedFixture) do(t *testing.T, url string) (int, string, context.Context) {
	t.Helper()
	var captured context.Context
	f.repo.EXPECT().ListAuditEvents(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, filter domain.UnifiedAuditEventFilter, offset, limit int) ([]domain.UnifiedAuditEvent, int64, error) {
			captured = ctx
			return []domain.UnifiedAuditEvent{{ID: 1, ActorID: "7", Service: "eiam", Domain: "operation", Action: "create", Result: "success", At: 1700000000000}}, int64(1), nil
		}).AnyTimes()

	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), captured
}

func TestFederationEvents(t *testing.T) {
	t.Run("闸门1：federation.enabled=false 时整体拒答（默认关闭）", func(t *testing.T) {
		f := newFedFixture(t, false, []int{3})
		_, body, _ := f.do(t, "/api/s2s/audit/events?tenant_id=3")
		assert.Contains(t, body, `"code":403`)
		assert.Contains(t, body, "未启用")
	})

	t.Run("闸门2：白名单为空 = 拒绝所有租户（fail-closed）", func(t *testing.T) {
		f := newFedFixture(t, true, []int{})
		_, body, _ := f.do(t, "/api/s2s/audit/events?tenant_id=3")
		assert.Contains(t, body, `"code":403`)
		assert.Contains(t, body, "未授权")
	})

	t.Run("白名单命中 → 租户上下文注入 + 数据返回", func(t *testing.T) {
		f := newFedFixture(t, true, []int{3})
		code, body, captured := f.do(t, "/api/s2s/audit/events?tenant_id=3&domain=operation")
		assert.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, `"total":1`)
		assert.Contains(t, body, `"actor_id":"7"`)
		require.NotNil(t, captured, "仓储层应收到注入租户后的上下文")
		assert.Equal(t, int64(3), ctxutil.GetTenantID(captured).Int64(), "租户上下文应来自白名单校验后的显式注入")
	})

	t.Run("白名单未命中租户 → 拒绝", func(t *testing.T) {
		f := newFedFixture(t, true, []int{3})
		_, body, _ := f.do(t, "/api/s2s/audit/events?tenant_id=9")
		assert.Contains(t, body, `"code":403`)
		assert.Contains(t, body, "未授权")
	})

	t.Run("缺少 tenant_id → 拒绝", func(t *testing.T) {
		f := newFedFixture(t, true, []int{3})
		_, body, _ := f.do(t, "/api/s2s/audit/events")
		assert.Contains(t, body, `"code":403`)
		assert.Contains(t, body, "缺少 tenant_id")
	})

	t.Run("tenant_id 非法（<=0）→ 拒绝", func(t *testing.T) {
		f := newFedFixture(t, true, []int{3})
		_, body, _ := f.do(t, "/api/s2s/audit/events?tenant_id=-1")
		assert.Contains(t, body, `"code":403`)
		assert.Contains(t, body, "非法")
	})

	t.Run("筛选维度透传（domain/service/time window）", func(t *testing.T) {
		f := newFedFixture(t, true, []int{3})
		var gotFilter domain.UnifiedAuditEventFilter
		f.repo.EXPECT().ListAuditEvents(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, filter domain.UnifiedAuditEventFilter, offset, limit int) ([]domain.UnifiedAuditEvent, int64, error) {
				gotFilter = filter
				return []domain.UnifiedAuditEvent{}, int64(0), nil
			})
		req := httptest.NewRequest(http.MethodGet, "/api/s2s/audit/events?tenant_id=3&domain=operation&service=eiam&start_time=1700000000000", nil)
		rec := httptest.NewRecorder()
		f.engine.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "operation", gotFilter.Domain)
		assert.Equal(t, "eiam", gotFilter.Service)
		assert.Equal(t, int64(1700000000000), gotFilter.StartTime)
	})
}
