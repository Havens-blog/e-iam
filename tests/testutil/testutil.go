// Package testutil provides shared test helpers for API functional tests
// of the watchalert-subproject-integration feature (eiam surface).
//
// @feature watchalert-subproject-integration
// @api-functional
package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/web/health"
	"github.com/Havens-blog/e-iam/internal/web/permission"
	userweb "github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/ecodeclub/ekit"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// --- Mock Auth Coordinator ---

// MockAuthCoordinator is a test double for usersvc.IAuthCoordinator.
type MockAuthCoordinator struct {
	AuthenticateFunc func(ctx context.Context, authType string, payload any) (domain.LoginResult, error)
	ResolveMfaFunc   func(ctx context.Context, token, code string) (domain.LoginResult, error)
	RecordLogoutFunc func(ctx context.Context, uid, tid int64, username string)
}

func (m *MockAuthCoordinator) Authenticate(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(ctx, authType, payload)
	}
	return domain.LoginResult{}, errs.ErrInvalidUser
}

func (m *MockAuthCoordinator) ResolveMfaChallenge(ctx context.Context, token, code string) (domain.LoginResult, error) {
	if m.ResolveMfaFunc != nil {
		return m.ResolveMfaFunc(ctx, token, code)
	}
	return domain.LoginResult{}, nil
}

func (m *MockAuthCoordinator) RecordLogout(ctx context.Context, uid, tid int64, username string) {
	if m.RecordLogoutFunc != nil {
		m.RecordLogoutFunc(ctx, uid, tid, username)
	}
}

// --- In-Memory Session Provider ---

// MemoryProvider is a thread-safe in-memory session provider for tests.
type MemoryProvider struct {
	mu       sync.Mutex
	sess     session.Session
	getErr   error
	destroyC int
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{}
}

func (p *MemoryProvider) SetSession(s session.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sess = s
}

func (p *MemoryProvider) SetGetError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getErr = err
}

func (p *MemoryProvider) DestroyCallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.destroyC
}

func (p *MemoryProvider) NewSession(ctx *gctx.Context, uid int64, jwtData map[string]string, sessData map[string]any) (session.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	claims := session.Claims{
		Uid:  uid,
		Data: jwtData,
	}
	s := session.NewMemorySession(claims)
	p.sess = s
	return s, nil
}

func (p *MemoryProvider) Get(ctx *gctx.Context) (session.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.getErr != nil {
		return nil, p.getErr
	}
	if p.sess == nil {
		return nil, errNoSession
	}
	return p.sess, nil
}

func (p *MemoryProvider) Destroy(ctx *gctx.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.destroyC++
	p.sess = nil
	return nil
}

func (p *MemoryProvider) UpdateClaims(ctx *gctx.Context, claims session.Claims) error {
	return nil
}

func (p *MemoryProvider) RenewAccessToken(ctx *gctx.Context) error {
	return nil
}

// errNoSession simulates "session not found" — uses ginx.ErrUnauthorized
// so ginx.W wrapper returns HTTP 401 instead of 500.
var errNoSession = ginx.ErrUnauthorized

// SessionNotFoundErr returns the error that triggers HTTP 401 in ginx wrappers.
// Use this when setting up a mock session provider to simulate "no valid session".
func SessionNotFoundErr() error { return ginx.ErrUnauthorized }

// --- Engine Builders ---

// SetupTestGin initializes gin test mode and returns a fresh engine.
func SetupTestGin() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

// BuildHealthEngine creates a gin engine with the eiam health endpoint (GET /health).
func BuildHealthEngine() *gin.Engine {
	engine := SetupTestGin()
	hh := health.NewHandler()
	hh.PublicRoutes(engine)
	return engine
}

// BuildLoginEngine creates a gin engine with eiam user login routes registered.
// The mockAuth parameter controls authentication behavior.
// A MemoryProvider is set as the default session provider and returned for inspection.
func BuildLoginEngine(mockAuth *MockAuthCoordinator) (*gin.Engine, *MemoryProvider) {
	engine := SetupTestGin()

	sp := NewMemoryProvider()
	session.SetDefaultProvider(sp)

	// Health endpoint
	hh := health.NewHandler()
	hh.PublicRoutes(engine)

	// User handler — nil for unused deps; sessionclaims.Build tolerates nil permSvc
	h := userweb.NewUserHandler(nil, mockAuth, nil, nil, nil, nil, nil)
	h.PublicRoutes(engine)

	// Logout route (requires session — uses ginx.S wrapper)
	h.IdentityRoutes(engine)

	return engine, sp
}

// BuildCheckLoginEngine creates a gin engine with the permission check_login route.
// A MemoryProvider is set as the default session provider and returned for inspection.
func BuildCheckLoginEngine() (*gin.Engine, *MemoryProvider) {
	engine := SetupTestGin()

	sp := NewMemoryProvider()
	session.SetDefaultProvider(sp)

	// Permission handler — nil for svc/matcher; CheckLogin only uses session.Get
	ph := permission.NewHandler(nil, nil)
	ph.PublicRoutes(engine)

	return engine, sp
}

// BuildWatchAlertSimEngine creates a gin engine simulating the WatchAlert router
// with local login REMOVED (no POST /api/system/login route).
func BuildWatchAlertSimEngine() *gin.Engine {
	engine := SetupTestGin()

	// Simulate WatchAlert routes WITHOUT local login
	v1 := engine.Group("api")
	system := v1.Group("system")
	// NOTE: POST /api/system/login is intentionally ABSENT (fact_id: WA_LOCAL_LOGIN_REMOVED)
	system.POST("register", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 0}) })
	system.GET("checkUser", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 0}) })

	watchalert := v1.Group("watchalert")
	watchalert.GET("auth-health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "ok",
			"data": gin.H{
				"probe_a":        "up",
				"probe_b":        "up",
				"write_disabled": false,
			},
		})
	})

	return engine
}

// --- Assertion Helpers ---

// APIResponse is the standard ginx response envelope.
type APIResponse struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// AssertHTTPStatus asserts the HTTP status code.
func AssertHTTPStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	require.Equal(t, want, w.Code, "expected HTTP %d, got %d, body: %s", want, w.Code, w.Body.String())
}

// AssertEnvelope asserts the HTTP status and the ginx.Result business code and message.
func AssertEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantHTTP int, wantCode int, wantMsgContains string) {
	t.Helper()
	require.Equal(t, wantHTTP, w.Code, "HTTP status mismatch, body: %s", w.Body.String())

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err, "failed to unmarshal: %s", w.Body.String())

	require.Equal(t, wantCode, resp.Code, "business code mismatch")
	if wantMsgContains != "" {
		require.Contains(t, resp.Msg, wantMsgContains, "message mismatch: %s", resp.Msg)
	}
}

// AssertResponseBodyContains asserts the raw response body contains a substring.
func AssertResponseBodyContains(t *testing.T, w *httptest.ResponseRecorder, substr string) {
	t.Helper()
	require.True(t, strings.Contains(w.Body.String(), substr),
		"body does not contain %q, got: %s", substr, w.Body.String())
}

// MakeJSONRequest creates an HTTP request with a JSON body.
func MakeJSONRequest(method, target string, body any) *http.Request {
	if body == nil {
		return httptest.NewRequest(method, target, nil)
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, target, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// MakeGETRequest creates a GET request without a body.
func MakeGETRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// SuccessLoginResult builds a domain.LoginResult for successful authentication.
func SuccessLoginResult(uid int64, username string, tid int64) domain.LoginResult {
	return domain.LoginResult{
		User:     domain.User{ID: uid, Username: username},
		TenantID: tid,
		Tenants:  []domain.Tenant{{ID: tid, Name: "test-tenant", Code: "test"}},
		AuthType: domain.LOCAL.String(),
	}
}

// AssertNoRoute verifies that the gin engine does NOT have a route matching method+path.
func AssertNoRoute(t *testing.T, engine *gin.Engine, method, path string) {
	t.Helper()
	for _, r := range engine.Routes() {
		if r.Method == method && r.Path == path {
			t.Fatalf("SECURITY REGRESSION: %s %s route is still registered", method, path)
		}
	}
}

// DummySession is a minimal session.Session for tests that need a pre-existing valid session.
type DummySession struct {
	ClaimsData session.Claims
}

func (d *DummySession) Set(ctx context.Context, key string, val any) error { return nil }
func (d *DummySession) Get(ctx context.Context, key string) ekit.AnyValue  { return ekit.AnyValue{} }
func (d *DummySession) Del(ctx context.Context, key string) error          { return nil }
func (d *DummySession) Destroy(ctx context.Context) error                  { return nil }
func (d *DummySession) Claims() session.Claims                             { return d.ClaimsData }
