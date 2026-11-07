package audit

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// FederationEvents 面向 e-cam-service 的 S2S 联邦读端点（统一审计 F1）。
//
// 安全模型（fail-closed，双闸门）：
//  1. 配置开关 audit.federation.enabled —— 默认 false，未显式启用前端点整体拒答；
//  2. 租户白名单 audit.federation.allowed_tenants —— 请求的 tenant_id 必须在
//     白名单内，否则拒绝。白名单为空 = 拒绝所有租户。
//
// 租户上下文经白名单校验后由 ctxutil.WithTenantID 显式注入，DAO 层 gormx
// 按该租户 fail-closed 过滤（无租户上下文的 SQL 直接阻断），联邦读不放大权限。
// 路由挂在 /api/s2s 组（S2STokenAuth 验签），不经用户会话/OPA 链路。
func (h *Handler) FederationEvents(ctx *ginx.Context) (ginx.Result, error) {
	if !viper.GetBool("audit.federation.enabled") {
		return ginx.Result{Code: http.StatusForbidden, Msg: "统一审计联邦读侧未启用"}, nil
	}

	tid, terr := resolveFederationTenant(ctx)
	if terr != nil {
		return ginx.Result{Code: http.StatusForbidden, Msg: terr.Error()}, nil
	}

	// 白名单校验通过后显式注入租户上下文（S2S 无会话，租户来自请求参数）；
	// DAO 层 gormx 按该租户 fail-closed 过滤，联邦读不放大权限。
	reqCtx := ctxutil.WithTenantID(ctx.Request.Context(), tid)

	filter := domain.UnifiedAuditEventFilter{
		Service:      queryStr(ctx, "service"),
		Domain:       queryStr(ctx, "domain"),
		Action:       queryStr(ctx, "action"),
		Result:       queryStr(ctx, "result"),
		ActorID:      queryStr(ctx, "actor_id"),
		ResourceType: queryStr(ctx, "resource_type"),
		StartTime:    queryInt64Or(queryStr(ctx, "start_time"), 0),
		EndTime:      queryInt64Or(queryStr(ctx, "end_time"), 0),
	}

	events, total, svcErr := h.svc.ListAuditEvents(reqCtx, filter,
		int(queryInt64Or(queryStr(ctx, "offset"), 0)),
		int(queryInt64Or(queryStr(ctx, "limit"), 20)),
	)
	if svcErr != nil {
		return ErrListAuditEventsFailed, svcErr
	}

	items := make([]AuditEventVO, 0, len(events))
	for _, item := range events {
		items = append(items, toAuditEventVO(item))
	}

	return ginx.Result{
		Data: gin.H{"total": total, "list": items},
	}, nil
}

// resolveFederationTenant 解析并校验请求租户：白名单
// （audit.federation.allowed_tenants）为空 = 拒绝所有租户（fail-closed）。
func resolveFederationTenant(ctx *ginx.Context) (int64, error) {
	raw := queryStr(ctx, "tenant_id")
	if raw == "" {
		return 0, errFederationTenantRequired
	}
	tid, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || tid <= 0 {
		return 0, errFederationTenantInvalid
	}
	allowed := viper.GetIntSlice("audit.federation.allowed_tenants")
	if !slices.Contains(allowed, int(tid)) {
		return 0, errFederationTenantNotAllowed
	}
	return tid, nil
}

// queryStr ginx.Query 返回 ekit.AnyValue（多值），收敛为 string（空安全）。
func queryStr(ctx *ginx.Context, key string) string {
	s, _ := ctx.Query(key).String()
	return s
}

// queryI64 ginx.Query 收敛为 int64（解析失败/缺失为 0）。
func queryI64(ctx *ginx.Context, key string) int64 {
	v, _ := ctx.Query(key).Int64()
	return v
}

func queryInt64Or(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	return fallback
}
