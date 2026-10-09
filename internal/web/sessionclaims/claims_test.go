package sessionclaims

import (
	"context"
	"errors"
	"strconv"
	"testing"

	permmocks "github.com/Havens-blog/e-iam/internal/service/permission/mocks"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestBuild 覆盖签约流程（登录 / 切换租户）的 claims 补全：
// - 查询前必须按签发租户注入上下文（否则 casbin 域匹配 "0" → 无 is_admin）
// - role:admin / role:super_admin 均产出 is_admin="true"
func TestBuild(t *testing.T) {
	testCases := []struct {
		name      string
		tenantID  int64
		codes     []string
		codesErr  error
		roles     []string
		rolesErr  error
		wantAdmin bool
		wantCodes bool
	}{
		{
			name:      "租户管理员(role:admin) → is_admin=true",
			tenantID:  2,
			codes:     []string{"cam:asset:view"},
			roles:     []string{"role:admin"},
			wantAdmin: true,
		},
		{
			name:      "系统空间 super_admin → is_admin=true",
			tenantID:  1,
			codes:     []string{"cert:issue"},
			roles:     []string{"role:super_admin"},
			wantAdmin: true,
			wantCodes: true, // cert:* 是下游消费子集
		},
		{
			name:     "普通角色 → 不携带 is_admin",
			tenantID: 2,
			codes:    []string{"cam:asset:view"},
			roles:    []string{"ops"},
		},
		{
			name:     "授权查询失败 → 降级为身份字段（无 is_admin）",
			tenantID: 2,
			codesErr: errors.New("manifest unreachable"),
			roles:    []string{"role:admin"},
		},
		{
			name:     "临时凭证(tenantID=0) → 不查询授权、无 is_admin",
			tenantID: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			permSvc := permmocks.NewMockIPermissionService(ctrl)

			if tc.tenantID != 0 {
				permSvc.EXPECT().
					GetAuthorizedCodes(gomock.Any(), "admin").
					DoAndReturn(func(ctx context.Context, username string) ([]string, error) {
						// 核心回归点：Build 必须把被签发租户注入查询上下文
						assert.Equal(t, tc.tenantID, ctxutil.GetTenantID(ctx).Int64())
						return tc.codes, tc.codesErr
					})
				permSvc.EXPECT().
					GetRolesForUser(gomock.Any(), "admin").
					DoAndReturn(func(ctx context.Context, username string) ([]string, error) {
						assert.Equal(t, tc.tenantID, ctxutil.GetTenantID(ctx).Int64())
						return tc.roles, tc.rolesErr
					})
			}

			data := Build(context.Background(), permSvc, nil, 42, "admin", tc.tenantID)

			assert.Equal(t, "admin", data["username"])
			assert.Equal(t, strconv.FormatInt(tc.tenantID, 10), data["tenant_id"])

			queryFailed := tc.codesErr != nil || tc.rolesErr != nil
			if tc.wantAdmin && !queryFailed {
				assert.Equal(t, "true", data["is_admin"])
			} else {
				assert.NotContains(t, data, "is_admin")
			}
			if tc.wantCodes && !queryFailed {
				assert.Contains(t, data, "authorized_codes")
			}
		})
	}
}
