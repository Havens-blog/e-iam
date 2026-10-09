package grpcx

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const testSecret = "test-secret-key"

// makeContextWithAuth 构造带 Authorization metadata 的 incoming context。
func makeContextWithAuth(token string) context.Context {
	md := metadata.Pairs(AuthorizationKey, token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// runInterceptor 直接调用拦截器并返回 (resp, err)。
func runInterceptor(t *testing.T, b *InterceptorBuilder, ctx context.Context) (interface{}, error) {
	t.Helper()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		// 验证 claims 已注入
		if _, ok := Get(ctx); !ok {
			return nil, errors.New("claims not injected into context")
		}
		return "ok", nil
	}
	return b.JwtAuthInterceptor()(ctx, nil, info, handler)
}

// signToken 用给定 secret 与 claims 生成 HS256 token，与生产路径一致。
func signToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return str
}

// TestJWT_ValidToken 有效 token 放行并注入 claims。
func TestJWT_ValidToken(t *testing.T) {
	b := NewJwtAuth(testSecret)
	token := signToken(t, testSecret, jwt.MapClaims{
		"sub":       "u1",
		"tenant_id": float64(1),
		"user_id":   float64(2),
		"iss":       DefaultIssuer,
	})

	ctx := makeContextWithAuth(BearerPrefix + token)
	resp, err := runInterceptor(t, b, ctx)
	if err != nil {
		t.Fatalf("expected pass, got error: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("expected ok, got %v", resp)
	}

	// 顺便验证无 Bearer 前缀也能解析（兼容路径）
	ctx2 := makeContextWithAuth(token)
	if _, err := runInterceptor(t, b, ctx2); err != nil {
		t.Fatalf("expected pass without Bearer prefix, got: %v", err)
	}
}

// TestJWT_MissingToken 无 token（无 metadata 或无 Authorization 头）拒绝。
func TestJWT_MissingToken(t *testing.T) {
	b := NewJwtAuth(testSecret)

	// 1. 完全无 metadata
	_, err := runInterceptor(t, b, context.Background())
	if err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}

	// 2. 有 metadata 但无 Authorization 头
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("foo", "bar"))
	_, err = runInterceptor(t, b, ctx)
	if err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// TestJWT_ExpiredToken 过期 token 拒绝。
func TestJWT_ExpiredToken(t *testing.T) {
	b := NewJwtAuth(testSecret)
	token := signToken(t, testSecret, jwt.MapClaims{
		"sub": "u1",
		"exp": 1, // 1970 年，必然已过期
	})

	ctx := makeContextWithAuth(BearerPrefix + token)
	_, err := runInterceptor(t, b, ctx)
	if err == nil {
		t.Fatal("expected expired error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
	if !errors.Is(err, jwt.ErrTokenExpired) && st.Message() != "授权令牌已过期" {
		// 拦截器把 ErrTokenExpired 映射成中文消息
		t.Fatalf("expected expired message, got %v", st.Message())
	}
}

// TestJWT_BadSignature 签名错误的 token 拒绝。
func TestJWT_BadSignature(t *testing.T) {
	b := NewJwtAuth(testSecret)
	// 用不同 secret 签发
	token := signToken(t, "wrong-secret", jwt.MapClaims{
		"sub": "u1",
	})

	ctx := makeContextWithAuth(BearerPrefix + token)
	_, err := runInterceptor(t, b, ctx)
	if err == nil {
		t.Fatal("expected signature invalid error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
	if st.Message() != "授权令牌签名无效" {
		t.Fatalf("expected signature invalid message, got %v", st.Message())
	}
}

// TestJWT_EncodeDecodeRoundTrip 验证 Encode 产出的 token 能被 Decode 校验通过。
func TestJWT_EncodeDecodeRoundTrip(t *testing.T) {
	b := NewJwtAuth(testSecret)
	token, err := b.Encode(jwt.MapClaims{
		"sub":       "u1",
		"tenant_id": float64(1),
		"user_id":   float64(2),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	claims, err := b.Decode(BearerPrefix + token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims["sub"] != "u1" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
	if claims["iss"] != DefaultIssuer {
		t.Fatalf("unexpected iss: %v", claims["iss"])
	}
}
