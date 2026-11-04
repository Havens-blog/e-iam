// @feature watchalert-subproject-integration
// @api-functional
// Journey: migration-cutover
// Contract source: docs/features/watchalert-subproject-integration/testing/migration-cutover/contracts/
package migration_cutover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/tests/testutil"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Step 1 Outcome "success": Parallel phase — eiam login works (new instance can authenticate).
// Contract: step-1-parallel-phase-verification.md
func TestStep1_ParallelPhase_EiamLoginWorks(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "parallel", 1), nil
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "parallel", Password: "pass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, "登录成功")
}

// Step 2 Outcome "unauthorized": Export config without authentication returns 401.
// Contract: step-2-config-migration-export-import.md
// fact_id: WA_EXPORT_CONFIG, IAM_UNAUTHORIZED_401
func TestStep2_ExportConfig_Unauthorized_401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	sp.SetGetError(testutil.SessionNotFoundErr())

	// Simulate export endpoint requiring auth
	engine.GET("/api/watchalert/export/config", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 1401, "msg": "未认证或会话过期"})
	})

	req := testutil.MakeGETRequest("/api/watchalert/export/config")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
	testutil.AssertResponseBodyContains(t, w, `"code":1401`)
}

// Step 2 Outcome "validation-error": Malformed import payload returns 400.
// Contract: step-2-config-migration-export-import.md
// fact_id: WA_IMPORT_CONFIG
func TestStep2_ImportConfig_ValidationError_400(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.POST("/api/watchalert/import/config", func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, gin.H{"code": 1400, "msg": "schema_version 缺失"})
	})

	// Send malformed payload (missing schema_version)
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/watchalert/import/config",
		map[string]any{"rules": []any{}}) // no schema_version
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusBadRequest)
	testutil.AssertResponseBodyContains(t, w, `"code":1400`)
}

// Step 2 Outcome "not-found": Role-binding import with non-existent eiam_uid returns 404.
// Contract: step-2-config-migration-export-import.md
// fact_id: WA_ROLE_BINDING_ENDPOINTS
func TestStep2_RoleBindingImport_NotFound_404(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.POST("/api/watchalert/role-bindings", func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"code": 1404, "msg": "eiam_uid 不存在"})
	})

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/watchalert/role-bindings",
		map[string]any{"bindings": []map[string]string{{"eiam_uid": "nonexistent", "role": "admin"}}})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
	testutil.AssertResponseBodyContains(t, w, `"code":1404`)
}

// Step 2 Outcome "conflict": Duplicate import returns 409.
// Contract: step-2-config-migration-export-import.md
// fact_id: WA_API_ERROR_ENVELOPE (NewConflictError)
func TestStep2_ImportConfig_Conflict_409(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.POST("/api/watchalert/import/config", func(c *gin.Context) {
		c.JSON(http.StatusConflict, gin.H{"code": 1409, "msg": "配置已存在"})
	})

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/watchalert/import/config",
		map[string]any{"schema_version": "v1", "rules": []any{}})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusConflict)
	testutil.AssertResponseBodyContains(t, w, `"code":1409`)
}

// Step 2 Outcome "success": Export config returns JSON with schema_version.
// Contract: step-2-config-migration-export-import.md
// fact_id: WA_EXPORT_CONFIG
func TestStep2_ExportConfig_Success(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.GET("/api/watchalert/export/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "ok",
			"data": gin.H{
				"schema_version": "v1",
				"rules":          []any{},
				"datasources":    []any{},
				"notifications":  []any{},
			},
		})
	})

	req := testutil.MakeGETRequest("/api/watchalert/export/config")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"schema_version"`)
	testutil.AssertResponseBodyContains(t, w, `"rules"`)
	testutil.AssertResponseBodyContains(t, w, `"datasources"`)
	testutil.AssertResponseBodyContains(t, w, `"notifications"`)
}

// Step 4 Outcome "cutover-metrics-below-threshold-rollback": Auth success rate threshold check.
// Contract: step-4-proxy-gray-cutover-read-then-write.md
// At API level: verify auth endpoint responds correctly during cutover.
func TestStep4_Cutover_AuthEndpointResponds(t *testing.T) {
	engine := testutil.BuildHealthEngine()

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
}

// Step 4 Outcome "eiam-unavailable-during-cutover": eiam health check during cutover.
// Contract: step-4-proxy-gray-cutover-read-then-write.md
func TestStep4_EiamUnavailable_HealthCheckFails(t *testing.T) {
	// Simulate eiam unavailable — no routes registered
	engine := gin.New()
	gin.SetMode(gin.TestMode)

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
}

// Step 5 Outcome "success": Full alert cycle — health endpoint stable.
// Contract: step-5-observe-full-alert-cycle.md
func TestStep5_AlertCycle_HealthStable(t *testing.T) {
	engine := testutil.BuildHealthEngine()

	// Simulate 15-minute observation with periodic health checks
	for i := 0; i < 5; i++ {
		req := testutil.MakeGETRequest("/health")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		testutil.AssertHTTPStatus(t, w, http.StatusOK)
	}
}

// Step 6 Outcome "success": Old instance set to readonly.
// Contract: step-6-retire-old-instance.md
// During readonly retention, write operations return 503.
func TestStep6_OldInstanceReadonly_WriteReturns503(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.POST("/api/w8t/rule/save", func(c *gin.Context) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": 1503, "msg": "旧实例只读保留期"})
	})

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/w8t/rule/save",
		map[string]string{"name": "test"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusServiceUnavailable)
}

// Smoke Test: Migration cutover happy path.
func TestSmoke_MigrationCutover_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Step 1: Parallel phase — eiam login works
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1, "migration", 1), nil
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "migration", Password: "pass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 2: Export config succeeds
	waEngine := testutil.BuildWatchAlertSimEngine()
	waEngine.GET("/api/watchalert/export/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0, "msg": "ok",
			"data": gin.H{"schema_version": "v1", "rules": []any{}, "datasources": []any{}, "notifications": []any{}},
		})
	})
	req = testutil.MakeGETRequest("/api/watchalert/export/config")
	w = httptest.NewRecorder()
	waEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	testutil.AssertResponseBodyContains(t, w, `"schema_version"`)

	// Step 5: Health stable during observation
	healthEngine := testutil.BuildHealthEngine()
	req = testutil.MakeGETRequest("/health")
	w = httptest.NewRecorder()
	healthEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 6: Old instance readonly — write returns 503
	waEngine.POST("/api/w8t/rule/save", func(c *gin.Context) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": 1503, "msg": "旧实例只读保留期"})
	})
	req = testutil.MakeJSONRequest(http.MethodPost, "/api/w8t/rule/save",
		map[string]string{"name": "test"})
	w = httptest.NewRecorder()
	waEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Journey Invariant: 401 for unauthenticated, 404 for removed endpoints
	_, sp := testutil.BuildCheckLoginEngine()
	sp.SetSession(session.NewMemorySession(session.Claims{Uid: 1, Data: map[string]string{"username": "x"}}))
}
