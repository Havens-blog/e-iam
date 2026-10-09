// Package sessionclaims 统一构建会话 JWT claims（方案 A：eiam 签发侧补全授权声明）。
//
// 背景：下游服务（如 e-cam-service 证书域 role_middleware）依赖 claims 中的
// is_admin / authorized_codes / permissions 推导操作者角色，而 issueSession
// 此前只写 tenant_id + username，导致已认证的管理员会话被下游判为无权限。
//
// 契约（与消费方 e-cam-service internal/cert/web/role_middleware.go 对齐）：
//   - is_admin：bool 字符串 "true"/"false"，命中 role:admin / role:super_admin
//   - authorized_codes：能力码 JSON 数组字符串（claims 为 map[string]string，
//     数组以序列化形态携带；消费方 parseClaimCodes 兼容 JSON 数组与逗号分隔）
//
// 查询失败不阻塞登录：降级为只写身份字段，与旧行为一致（deny-by-default
// 的下游会将该会话视为只读查看者）。
package sessionclaims

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/gotomicro/ego/core/elog"
)

// consumedPrefixes 下游服务从 claims 消费 authorized_codes 时实际使用的能力码前缀。
// 浏览器单 cookie 上限约 4KB，携带全量能力码会使 JWT 超限、被浏览器静默丢弃，
// 导致登录后所有请求 401。因此只携带下游真正读取的子集
// （当前唯一消费方 e-cam-service 证书域 role_middleware 匹配 cert:*）。
var consumedPrefixes = []string{"cert:"}

// filterConsumedCodes 过滤出下游实际消费的能力码子集
func filterConsumedCodes(codes []string) []string {
	var out []string
	for _, c := range codes {
		for _, p := range consumedPrefixes {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// Build 为指定用户构建完整 JWT data（身份字段 + 授权声明）。
// tenantID=0 代表临时凭证（等待选择租户），此时不附加授权声明——
// 正式会话在租户确定后签发（登录流程或 SwitchTenant）。
func Build(ctx context.Context, permSvc permission.IPermissionService, logger *elog.Component, uid int64, username string, tenantID int64) map[string]string {
	data := map[string]string{
		"tenant_id": strconv.FormatInt(tenantID, 10),
		"username":  username,
	}
	if tenantID == 0 || permSvc == nil {
		return data
	}

	var (
		codes []string
		roles []string
	)
	codes, codesErr := permSvc.GetAuthorizedCodes(ctx, username)
	roles, rolesErr := permSvc.GetRolesForUser(ctx, username)
	if codesErr != nil || rolesErr != nil {
		// 授权中心查询失败不阻塞登录：降级为身份字段（旧行为），
		// 记录错误供排查——下游 deny-by-default，影响面收敛为只读。
		if logger != nil {
			logger.Error("构建会话授权声明失败，降级为仅身份字段",
				elog.Int64("uid", uid),
				elog.String("username", username),
				elog.FieldErr(codesErr),
				elog.Any("rolesErr", rolesErr))
		}
		return data
	}

	// 只携带下游消费的能力码子集，控制 cookie 体积（见 consumedPrefixes 注释）
	if filtered := filterConsumedCodes(codes); len(filtered) > 0 {
		raw, err := json.Marshal(filtered)
		if err == nil {
			data["authorized_codes"] = string(raw)
		}
	}
	if domain.HasAdminRole(roles) {
		data["is_admin"] = "true"
	}
	return data
}
