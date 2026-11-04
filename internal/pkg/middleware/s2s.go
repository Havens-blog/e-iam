package middleware

import (
	"net/http"
	"strings"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ITokenVerifier S2S 服务令牌验签所需的最小接口契约。
// oidc.IKeyManager 的 VerifyJWT 方法天然满足,中间件不依赖 oidc 包,避免耦合。
type ITokenVerifier interface {
	VerifyJWT(tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

// S2STokenAuth 服务间调用鉴权中间件:
// 校验 client_credentials 签发的 RS256 JWT,解出 tenant_id 注入租户上下文。
// fail-closed:无 token / 验签失败 / 缺租户 一律拒绝。
//
// 下游业务 handler(如 tenant.Detail)已含「currentTid != 请求 id 则拒绝」的越权校验,
// 因此此处注入的 tenant_id 会被下游自动比对,天然实现「服务只能查它被授权代表的租户」。
func S2STokenAuth(verifier ITokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少服务令牌"})
			return
		}

		var claims domain.IDTokenClaims
		if _, err := verifier.VerifyJWT(token, &claims); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "服务令牌无效或已过期"})
			return
		}

		// fail-closed:业务端点要求服务 token 必须携带租户上下文
		if claims.TenantID <= 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "服务令牌缺少租户上下文"})
			return
		}

		c.Request = c.Request.WithContext(ctxutil.WithTenantID(c.Request.Context(), claims.TenantID))
		c.Next()
	}
}
