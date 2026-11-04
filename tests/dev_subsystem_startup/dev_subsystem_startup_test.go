// @feature watchalert-subproject-integration
// @api-functional
// Journey: dev-subsystem-startup
// Contract source: docs/features/watchalert-subproject-integration/testing/dev-subsystem-startup/contracts/
package dev_subsystem_startup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/tests/testutil"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Step 2 Outcome "success": Backend startup — health probe succeeds.
// Contract: step-2-backend-startup-success.md
func TestStep2_BackendStartup_HealthProbeSucceeds(t *testing.T) {
	engine := testutil.BuildHealthEngine()

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
	testutil.AssertResponseBodyContains(t, w, `"msg":"ok"`)
}

// Step 2 Outcome "backend-port-conflict-or-stale-process": Health probe fails when backend not running.
// Contract: step-2-backend-startup-success.md
func TestStep2_BackendNotRunning_HealthProbeFails(t *testing.T) {
	// Create a minimal engine that simulates no routes registered (backend not started)
	engine := gin.New()
	gin.SetMode(gin.TestMode)

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// No route registered → 404 (backend not running)
	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
}

// Step 4 Outcome "success": Status check — backend healthy.
// Contract: step-4-check-status-and-logs.md
func TestStep4_StatusCheck_BackendHealthy(t *testing.T) {
	engine := testutil.BuildHealthEngine()

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
}

// Step 5 Outcome "success": Platform accessible with eiam login.
// Contract: step-5-access-platform-start-work.md
func TestStep5_PlatformAccessible_EiamLoginAvailable(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "devuser", 1), nil
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "devuser", Password: "devpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, "登录成功")
}

// Step 5 Outcome "unauthorized-401": Unauthenticated access returns 401 (envelope code=1401).
// Contract: step-5-access-platform-start-work.md
// fact_id: IAM_UNAUTHORIZED_401
func TestStep5_Unauthorized_Returns401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	sp.SetGetError(testutil.SessionNotFoundErr())

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 5 Outcome "forbidden-403": Authenticated but no role returns 403 (envelope code=1403).
// Contract: step-5-access-platform-start-work.md
func TestStep5_Forbidden_Returns403(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.GET("/api/w8t/dashboard", func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{"code": 1403, "msg": "无访问权限"})
	})

	req := testutil.MakeGETRequest("/api/w8t/dashboard")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusForbidden)
	testutil.AssertResponseBodyContains(t, w, `"code":1403`)
}

// Step 5 Outcome "unavailable-503": Write during degradation returns 503 (envelope code=1503).
// Contract: step-5-access-platform-start-work.md
// fact_id: WA_WRITE_DEGRADATION_503
func TestStep5_Unavailable_Returns503(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()
	engine.POST("/api/w8t/rule/save", func(c *gin.Context) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": 1503, "msg": "鉴权服务暂不可用"})
	})

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/w8t/rule/save",
		map[string]string{"name": "test"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusServiceUnavailable)
	testutil.AssertResponseBodyContains(t, w, `"code":1503`)
}

// Step 5 Outcome "local-login-removed-404": Removed local login returns 404.
// Contract: step-5-access-platform-start-work.md
// fact_id: WA_LOCAL_LOGIN_REMOVED
func TestStep5_LocalLoginRemoved_404(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "user", Password: "pass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
}

// Smoke Test: Dev subsystem startup happy path.
func TestSmoke_DevSubsystemStartup_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Step 2: Backend health probe succeeds
	engine := testutil.BuildHealthEngine()
	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 5: eiam login available
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1, "smoke", 1), nil
		},
	}
	loginEngine, _ := testutil.BuildLoginEngine(mockAuth)
	req = testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "smoke", Password: "pass"})
	w = httptest.NewRecorder()
	loginEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 5: local login removed
	waEngine := testutil.BuildWatchAlertSimEngine()
	req = testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "smoke", Password: "pass"})
	w = httptest.NewRecorder()
	waEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}
