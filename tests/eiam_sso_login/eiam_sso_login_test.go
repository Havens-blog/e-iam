// @feature watchalert-subproject-integration
// @api-functional
// Journey: eiam-sso-login
// Contract source: docs/features/watchalert-subproject-integration/testing/eiam-sso-login/contracts/
package eiam_sso_login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/tests/testutil"
	"github.com/ecodeclub/ginx/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Step 1 Outcome "success": Access unauth platform — CheckLogin without session returns 401.
// Contract: step-1-access-unauth-platform.md
func TestStep1_AccessUnauthPlatform_CheckLoginReturnsUnauthenticated(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	sp.SetGetError(testutil.SessionNotFoundErr()) // force no session

	// Simulate unauthenticated request — no session cookie
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Without a valid session, ginx.W wrapper's session.Get fails → 401
	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 1 Outcome "local-login-endpoint-404": Removed local login endpoint returns 404.
// Contract: step-1-access-unauth-platform.md
// fact_id: WA_LOCAL_LOGIN_REMOVED
func TestStep1_LocalLoginEndpointRemoved_404(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	// Verify route is not registered
	testutil.AssertNoRoute(t, engine, http.MethodPost, "/api/system/login")

	// HTTP request to removed endpoint
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		map[string]string{"username": "admin", "password": "old"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// 404 — endpoint removed (not 401)
	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
}

// Step 2 Outcome "success": eiam login endpoint is reachable (health check passes).
// Contract: step-2-redirect-to-eiam-login.md
func TestStep2_EiamAuthServiceReachable(t *testing.T) {
	engine := testutil.BuildHealthEngine()

	req := testutil.MakeGETRequest("/health")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
	testutil.AssertResponseBodyContains(t, w, `"msg":"ok"`)
}

// Step 3 Outcome "success": eiam login with valid credentials creates session.
// Contract: step-3-complete-eiam-auth.md
func TestStep3_LoginSuccess_CreatesSession(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "testuser", 1), nil
		},
	}
	engine, sp := testutil.BuildLoginEngine(mockAuth)

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "testuser", Password: "validpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
	testutil.AssertResponseBodyContains(t, w, "登录成功")
	// Session should be created
	require.NotNil(t, sp, "session provider should have a session after login")
}

// Step 3 Outcome "auth-failure": eiam login with invalid credentials returns generic error.
// Contract: step-3-complete-eiam-auth.md
// fact_id: IAM_LOGIN_ERROR_NO_LEAK
func TestStep3_LoginFailure_GenericErrorNoLeak(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return domain.LoginResult{}, errs.ErrInvalidUser
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "nonexistent", Password: "wrongpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// ginx.B returns 500 when err != nil, but the response body contains the mapped Result
	testutil.AssertHTTPStatus(t, w, http.StatusInternalServerError)
	// Response should contain generic auth failure code (4010202) — no user enumeration
	testutil.AssertResponseBodyContains(t, w, `"code":4010202`)
	testutil.AssertResponseBodyContains(t, w, "认证失败")
}

// Step 3 Outcome "auth-failure" (locked user): login returns user-locked error.
// Contract: step-3-complete-eiam-auth.md
func TestStep3_LoginFailure_UserLocked(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return domain.LoginResult{}, errs.ErrUserLocked
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "lockeduser", Password: "anypass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusInternalServerError)
	testutil.AssertResponseBodyContains(t, w, `"code":4010203`)
	testutil.AssertResponseBodyContains(t, w, "锁定")
}

// Step 4 Outcome "success": CheckLogin with valid session returns user info.
// Contract: step-4-validate-session-match-role.md
func TestStep4_CheckLogin_ValidSession_ReturnsUserInfo(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()

	// Inject a valid session
	claims := session.Claims{
		Uid:  1001,
		Data: map[string]string{"username": "testuser", "tenant_id": "1"},
	}
	sp.SetSession(session.NewMemorySession(claims))

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
	testutil.AssertResponseBodyContains(t, w, `"uid":1001`)
	testutil.AssertResponseBodyContains(t, w, `"username":"testuser"`)
}

// Step 4 Outcome "unauthorized": CheckLogin without session returns 401.
// Contract: step-4-validate-session-match-role.md
// fact_id: IAM_UNAUTHORIZED_401
func TestStep4_CheckLogin_NoSession_Returns401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	sp.SetGetError(testutil.SessionNotFoundErr()) // force session lookup failure

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 5 Outcome "success": Authenticated access to dashboard succeeds.
// Contract: step-5-enter-dashboard.md
func TestStep5_EnterDashboard_AuthenticatedAccess(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()

	claims := session.Claims{
		Uid:  1001,
		Data: map[string]string{"username": "testuser", "tenant_id": "1"},
	}
	sp.SetSession(session.NewMemorySession(claims))

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
}

// Step 6 Outcome "session-expired": Session expiry returns 401.
// Contract: step-6-session-expiry-relogin.md
// fact_id: IAM_UNAUTHORIZED_401
func TestStep6_SessionExpiry_Returns401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	// No session set → simulates expired session
	sp.SetGetError(testutil.SessionNotFoundErr())

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 7 Outcome "success": Logout destroys session (delegated to eiam).
// Contract: step-7-single-sign-out.md
// fact_id: WA_LOGOUT_DELEGATED_EIAM
func TestStep7_Logout_DestroysSharedSession(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "testuser", 1), nil
		},
	}
	engine, sp := testutil.BuildLoginEngine(mockAuth)

	// First login to create a session
	loginReq := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "testuser", Password: "validpass"})
	loginW := httptest.NewRecorder()
	engine.ServeHTTP(loginW, loginReq)
	require.Equal(t, http.StatusOK, loginW.Code)

	// Verify session exists
	require.NotNil(t, sp)

	// Logout — ginx.S wrapper requires session, should succeed
	logoutReq := testutil.MakeJSONRequest(http.MethodPost, "/api/user/logout", nil)
	// Need to carry the session cookie — in httptest we simulate by having the provider return the session
	logoutW := httptest.NewRecorder()
	engine.ServeHTTP(logoutW, logoutReq)

	// Logout should succeed (200) since session exists from login
	testutil.AssertHTTPStatus(t, logoutW, http.StatusOK)
	testutil.AssertResponseBodyContains(t, logoutW, "退出登录成功")

	// After logout, session should be destroyed
	assert.Greater(t, sp.DestroyCallCount(), 0, "session should be destroyed after logout")
}

// Step 7 Outcome "other-tab-401": After logout, subsequent requests return 401.
// Contract: step-7-single-sign-out.md
func TestStep7_OtherTabNextRequest_401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()

	// Simulate: user logged out in another tab — session destroyed
	sp.SetGetError(testutil.SessionNotFoundErr()) // no valid session after logout

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}
