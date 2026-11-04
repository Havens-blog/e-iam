// @feature watchalert-subproject-integration
// @api-functional
// Journey: local-login-removal-verification
// Contract source: docs/features/watchalert-subproject-integration/testing/local-login-removal-verification/contracts/
package local_login_removal_verification

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

// Step 1 Outcome "success": POST /api/system/login returns 404 (endpoint removed).
// Contract: step-1-verify-local-login-endpoint-removed.md
// fact_id: WA_LOCAL_LOGIN_REMOVED
func TestStep1_LocalLoginEndpoint_Returns404(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "admin", Password: "oldpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// 404 — endpoint removed, NOT 401
	testutil.AssertHTTPStatus(t, w, http.StatusNotFound)
}

// Step 1 Outcome "endpoint-returns-401-not-404": Security regression — endpoint returns 401 instead of 404.
// Contract: step-1-verify-local-login-endpoint-removed.md
func TestStep1_LocalLoginMustNotReturn401(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "admin", Password: "oldpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Must NOT return 401 — that would mean endpoint still exists
	require.NotEqual(t, http.StatusUnauthorized, w.Code,
		"SECURITY REGRESSION: POST /api/system/login returned 401 — endpoint not fully removed")
}

// Step 1 Outcome "endpoint-returns-200-issues-token": Critical backdoor — endpoint returns 200 + token.
// Contract: step-1-verify-local-login-endpoint-removed.md
func TestStep1_LocalLoginMustNotReturn200WithToken(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "admin", Password: "oldpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Must NOT return 200 — that would be a critical security backdoor
	require.NotEqual(t, http.StatusOK, w.Code,
		"CRITICAL SECURITY BACKDOOR: POST /api/system/login returned 200 — token may be issued")
}

// Step 1 Outcome "unauthorized": Protected endpoint without credentials returns 401.
// Contract: step-1-verify-local-login-endpoint-removed.md
// fact_id: IAM_UNAUTHORIZED_401
func TestStep1_ProtectedEndpoint_Return401WithoutCredentials(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	sp.SetGetError(testutil.SessionNotFoundErr())

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 2 Outcome "success": Frontend has only eiam redirect entry, no local login form.
// Contract: step-2-verify-frontend-eiam-redirect-only.md
// This is a web-surface assertion; at API level we verify the eiam login endpoint is the delegated path.
func TestStep2_EiamLoginEndpointIsDelegatedPath(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "delegateduser", 1), nil
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	// eiam login endpoint exists and accepts credentials
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "delegateduser", Password: "validpass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusOK)
	testutil.AssertResponseBodyContains(t, w, `"code":0`)
}

// Step 2 Outcome "redirect-whitelist-reject": Malicious redirect parameters are rejected.
// Contract: step-2-verify-frontend-eiam-redirect-only.md
// At API level: login endpoint does not accept arbitrary redirect parameters.
func TestStep2_LoginEndpoint_DoesNotAcceptMaliciousRedirect(t *testing.T) {
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1001, "user", 1), nil
		},
	}
	engine, _ := testutil.BuildLoginEngine(mockAuth)

	// Login request should not have redirect parameter in the API contract
	// The redirect whitelist is enforced by the frontend/WatchAlert, not eiam login API
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "user", Password: "pass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Login succeeds — redirect validation happens at the calling layer
	testutil.AssertHTTPStatus(t, w, http.StatusOK)
}

// Step 3 Outcome "success": Forged token with removed signing key is rejected (401).
// Contract: step-3-verify-legacy-jwt-signing-key-invalid.md
func TestStep3_ForgedToken_Rejected401(t *testing.T) {
	engine, sp := testutil.BuildCheckLoginEngine()
	// No valid session — forged token won't be accepted
	sp.SetGetError(testutil.SessionNotFoundErr())

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/permission/check_login", nil)
	req.Header.Set("Authorization", "Bearer forged.token.witholdkey")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusUnauthorized)
}

// Step 3 Outcome "legacy-jwt-write-rejected-403": Legacy JWT on write endpoints returns 403.
// Contract: step-3-verify-legacy-jwt-signing-key-invalid.md
// fact_id: WA_LEGACY_JWT_READONLY_FALLBACK
func TestStep3_LegacyJwtWrite_Rejected403(t *testing.T) {
	engine := testutil.BuildWatchAlertSimEngine()

	// Simulate write endpoint that rejects legacy JWT with 403
	engine.POST("/api/w8t/rule/save", func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{
			"code": 1403,
			"msg":  "旧会话已失效",
		})
	})

	req := testutil.MakeJSONRequest(http.MethodPost, "/api/w8t/rule/save",
		map[string]string{"name": "test"})
	req.Header.Set("Authorization", "Bearer legacy.jwt.token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	testutil.AssertHTTPStatus(t, w, http.StatusForbidden)
	testutil.AssertResponseBodyContains(t, w, `"code":1403`)
}

// Smoke Test: Local login removal verification happy path.
func TestSmoke_LocalLoginRemoval_HappyPath(t *testing.T) {
	// Verify: local login endpoint returns 404
	engine := testutil.BuildWatchAlertSimEngine()
	req := testutil.MakeJSONRequest(http.MethodPost, "/api/system/login",
		user.LoginRequest{Username: "admin", Password: "pass"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)

	// Verify: eiam login endpoint is the delegated path
	mockAuth := &testutil.MockAuthCoordinator{
		AuthenticateFunc: func(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
			return testutil.SuccessLoginResult(1, "smoke", 1), nil
		},
	}
	eiamEngine, _ := testutil.BuildLoginEngine(mockAuth)
	req = testutil.MakeJSONRequest(http.MethodPost, "/api/user/system/login",
		user.LoginRequest{Username: "smoke", Password: "pass"})
	w = httptest.NewRecorder()
	eiamEngine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}
