package grant

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/service/idp/claims"
)

// clientCredentialsGrantHandler 实现 OAuth 2.0 client_credentials 授权模式:
// 服务间调用(EIAM 唯一签发方)用 client_id/secret 换取携带租户授权范围的 access token。
// 无用户交互,故只签 access token(无 id_token/refresh_token)。
type clientCredentialsGrantHandler struct {
	signer         IKeySigner
	accessTokenTTL time.Duration
	secLogFn       func(ctx context.Context, app domain.Application, action, failReason string)
}

// NewClientCredentialsGrantHandler 构造 S2S 客户端凭证授权策略实例。
func NewClientCredentialsGrantHandler(
	signer IKeySigner,
	secLogFn func(ctx context.Context, app domain.Application, action, failReason string),
) IGrantHandler {
	return &clientCredentialsGrantHandler{
		signer:         signer,
		accessTokenTTL: 15 * time.Minute, // 服务 token 短 TTL,降低泄露窗口
		secLogFn:       secLogFn,
	}
}

func (h *clientCredentialsGrantHandler) GrantType() string {
	return "client_credentials"
}

func (h *clientCredentialsGrantHandler) Handle(ctx context.Context, req domain.TokenRequest, app domain.Application, issuerURL string) (*domain.OidcTokenResult, error) {
	// 1. 机密客户端校验:公共客户端(无密钥)禁止 S2S
	if app.IsPublic {
		return nil, fmt.Errorf("公共客户端不允许 client_credentials 授权模式")
	}

	// 2. 客户端凭证校验(复用现有 bcrypt 校验)
	if !app.VerifySecret(req.ClientSecret) {
		return nil, errs.ErrApplicationSecretWrong
	}

	// 3. 租户授权范围校验(fail-closed):带了 tenant_id 就必须通过 CanRepresentTenant
	if req.TenantID > 0 && !app.CanRepresentTenant(req.TenantID) {
		if h.secLogFn != nil {
			h.secLogFn(ctx, app, "s2s_tenant_forbidden", strconv.FormatInt(req.TenantID, 10))
		}
		return nil, fmt.Errorf("client [%s] 无权代表租户 %d", app.ClientID, req.TenantID)
	}

	// 4. 构造服务主体 claims(sub = client_id,租户可选)
	svcClaims := claims.FromService(app.ClientID, req.TenantID)

	// 5. 只签 access token(短 TTL;无 id_token:无用户身份)
	token, err := h.signer.SignJWT(buildClaims(TokenPayload{
		IssuerURL: issuerURL,
		ClientID:  app.ClientID,
		Claims:    svcClaims,
	}, strings.TrimRight(issuerURL, "/"), time.Now(), h.accessTokenTTL, ""))
	if err != nil {
		return nil, fmt.Errorf("签发服务令牌失败: %w", err)
	}

	return &domain.OidcTokenResult{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.accessTokenTTL.Seconds()),
	}, nil
}
