package grant

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSigner struct {
	lastClaims jwt.Claims
	err        error
}

func (f *fakeSigner) SignJWT(claims jwt.Claims) (string, error) {
	f.lastClaims = claims
	if f.err != nil {
		return "", f.err
	}
	return "signed-token", nil
}

func newConfidentialApp(public bool, allowed []int64) domain.Application {
	app := domain.Application{
		ClientID:       "e-cam-service",
		IsPublic:       public,
		AllowedTenants: allowed,
	}
	_ = app.SetSecret("s3cr3t")
	return app
}

// TestClientCredentialsGrantHandler_Handle 表驱动覆盖 S2S 令牌签发的安全分支:
// 机密校验 / 凭证校验 / 租户授权范围 / 无租户签发 / 签发失败。
func TestClientCredentialsGrantHandler_Handle(t *testing.T) {
	testCases := []struct {
		name    string
		app     domain.Application
		req     domain.TokenRequest
		signErr error
		wantErr bool
		wantTid int64
	}{
		{
			name:    "公共客户端拒绝",
			app:     newConfidentialApp(true, []int64{3}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 3},
			wantErr: true,
		},
		{
			name:    "客户端凭证错误拒绝",
			app:     newConfidentialApp(false, []int64{3}),
			req:     domain.TokenRequest{ClientSecret: "wrong", TenantID: 3},
			wantErr: true,
		},
		{
			name:    "租户越权拒绝",
			app:     newConfidentialApp(false, []int64{3, 5}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 99},
			wantErr: true,
		},
		{
			name:    "授权通过签发并携带租户",
			app:     newConfidentialApp(false, []int64{3, 5}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 3},
			wantErr: false,
			wantTid: 3,
		},
		{
			name:    "全租户通配签发任意租户",
			app:     newConfidentialApp(false, []int64{-1}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 99},
			wantErr: false,
			wantTid: 99,
		},
		{
			name:    "无租户签发纯服务身份令牌",
			app:     newConfidentialApp(false, []int64{}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 0},
			wantErr: false,
			wantTid: 0,
		},
		{
			name:    "签发失败透传错误",
			app:     newConfidentialApp(false, []int64{3}),
			req:     domain.TokenRequest{ClientSecret: "s3cr3t", TenantID: 3},
			signErr: assert.AnError,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{err: tc.signErr}
			h := NewClientCredentialsGrantHandler(signer, nil)
			res, err := h.Handle(context.Background(), tc.req, tc.app, "https://iam.example.com")

			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "Bearer", res.TokenType)
			assert.Equal(t, "signed-token", res.AccessToken)
			// 无 id_token(无用户身份)
			assert.Empty(t, res.IDToken)

			idc, ok := signer.lastClaims.(domain.IDTokenClaims)
			require.True(t, ok)
			assert.Equal(t, tc.wantTid, idc.TenantID)
			assert.Equal(t, "e-cam-service", idc.Subject)
		})
	}
}
