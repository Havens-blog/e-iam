// @feature watchalert-subproject-integration
// @api-functional
// Journey: eiam-sso-login — Smoke Test (happy path)
package eiam_sso_login

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

// SmokeTest: Complete SSO login happy path — health check → login → check_login → logout.
func TestSmoke_EiamSsoLogin_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// --- Step 1: Access unauth platform — local login endpoint returns 404 ---
	waEngine := testutil.BuildWatchAlertSimEngine()
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "admin", Password: "pass"})
	w := httptest.NewRecorder()
	waEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code, "removed local login must return 404")

	// --- Step 2: eiam auth service reachable (health probe) ---
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "smokeuser", 1), nil
		},
	}
	engine, sp := testutil.BuildLoginEngine(mockAuth)

	req = testutil.MakeGETRequest("/health")
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// --- Step 3: Complete eiam auth — login success ---
	req = testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "smokeuser", Password: "validpass"})
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
	testutil.AssertResponseBodyContains(t, w, "登录成功")

	// --- Step 4: Validate session — CheckLogin returns user info ---
	checkEngine, checkSP := testutil.BuildCheckLoginEngine()
	claims := session.Claims{
		Uid:  1001,
		Data: map[string]string{"username": "smokeuser", "tenant_id": "1"},
	}
	checkSP.SetSession(session.NewMemorySession(claims))

	req = testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w = httptest.NewRecorder()
	checkEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	testutil.AssertResponseBodyContains(t, w, `"uid":1001`)

	// --- Step 5: Enter dashboard — authenticated access succeeds ---
	// (covered by Step 4 CheckLogin returning 200 + user info)

	// --- Step 6: Session active — not expired ---
	// (covered by Step 4 returning 200 instead of 401)

	// --- Step 7: Single sign-out — logout destroys session ---
	// Re-set session provider to login engine's provider (Step 4 overrode it)
	session.SetDefaultProvider(sp)
	logoutReq := testutil.MakeJSONRequest(http.MethodPost, "/api/user/logout", nil)
	logoutW := httptest.NewRecorder()
	engine.ServeHTTP(logoutW, logoutReq)
	require.Equal(t, http.StatusOK, logoutW.Code)
	testutil.AssertResponseBodyContains(t, logoutW, "退出登录成功")
	require.Greater(t, sp.DestroyCallCount(), 0, "session must be destroyed after logout")

	// --- Journey Invariant: 401 for unauthenticated, 404 for removed endpoints ---
	// (verified in step tests)
}
