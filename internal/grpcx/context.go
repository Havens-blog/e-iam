package grpcx

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
)

// claimsKey 是注入 context 的受信 JWT claims 的键，避免导出暴露。
type claimsKey struct{}

// Set 将受信的 JWT Claims 注入 Context。
//
// 与 etask interceptors/jwt/context.go 不同，这里直接注入完整的 MapClaims，
// 不再拆分 tenant_id/user_id 到 ctxutil —— eiam 的 gRPC 服务按请求字段取数，
// 不依赖注入的强类型 ID，保留完整 claims 供下游按需读取。
func Set(ctx context.Context, claims jwt.MapClaims) context.Context {
	if claims == nil {
		return ctx
	}
	return context.WithValue(ctx, claimsKey{}, claims)
}

// Get 从 Context 中取出受信 JWT Claims。
func Get(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(jwt.MapClaims)
	return claims, ok
}
