package audit

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Havens-blog/e-iam/internal/domain"
	auditevt "github.com/Havens-blog/e-iam/internal/event/audit"
	auditsvc "github.com/Havens-blog/e-iam/internal/service/audit"
	"github.com/Havens-blog/e-iam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// Handler 审计 HTTP 控制器
type Handler struct {
	capability.IRegistry
	svc      auditsvc.IAuditService
	producer auditevt.IAuditProducer
}

// NewHandler 构建审计 Web 控制器实例
func NewHandler(svc auditsvc.IAuditService, producer auditevt.IAuditProducer) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "audit", "安全审计"),
		svc:       svc,
		producer:  producer,
	}
}

// reportAuthMiddleware 守护批量上报端点，防匿名审计投毒/栽赃/DoS。
// fail-closed：audit.report_token 未配置时直接拒绝所有上报（强制运维显式配置）；
// 配置后以恒定时间比较校验 Bearer 令牌，令牌与服务绑定由上报方保证。
func (h *Handler) reportAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		expected := viper.GetString("audit.report_token")
		if expected == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "审计上报令牌未配置，批量上报已禁用"})
			return
		}
		authHeader := c.GetHeader("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "无效的审计上报令牌"})
			return
		}
		c.Next()
	}
}

// PublicRoutes 注册开放给微服务 SDK 的批量上报端点（须携带上报令牌）
func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/audit")
	g.Use(h.reportAuthMiddleware())
	g.POST("/batch", ginx.B[BatchOperationReq](h.ReportBatchOperations))
}

// ReportBatchOperations 接收微服务 SDK 批量聚合上报的操作审计日志 (零阻塞入队)
func (h *Handler) ReportBatchOperations(ctx *ginx.Context, req BatchOperationReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()
	lo.ForEach(req.Records, func(r OperationLogRecord, _ int) {
		_ = h.producer.RecordOperation(reqCtx, domain.OperationLog{
			TenantID:     r.TenantID,
			Service:      r.Service,
			OperatorID:   r.OperatorID,
			OperatorName: sanitizeAuditText(r.OperatorName),
			Module:       sanitizeAuditText(r.Module),
			Action:       sanitizeAuditText(r.Action),
			ResourceID:   sanitizeAuditText(r.ResourceID),
			ResourceName: sanitizeAuditText(r.ResourceName),
			ResourceURN:  sanitizeAuditText(r.ResourceURN),
			// AfterState 为自由文本，前端审计查看页若未转义可触发存储型 XSS；
			// 此处截断长度上限，后续渲染须强制转义。
			AfterState: sanitizeAuditText(r.AfterState),
			Status:     r.Status,
			FailReason: sanitizeAuditText(r.FailReason),
			ClientIP:   r.ClientIP,
			UserAgent:  r.UserAgent,
			Ctime:      r.Ctime,
		})
	})
	return ginx.Result{Msg: "ok"}, nil
}

// maxAuditTextLen 审计自由文本字段长度上限，防超长负载撑爆审计表/日志注入。
const maxAuditTextLen = 4096

// sanitizeAuditText 截断自由文本字段上限，降低日志注入与存储 XSS 拼面。
// 最终防 XSS 仍依赖前端渲染强制转义，此处仅做长度收敛。
func sanitizeAuditText(s string) string {
	if len(s) > maxAuditTextLen {
		return s[:maxAuditTextLen]
	}
	return s
}

// PrivateRoutes 注册审计管理私有路由
func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/audit")

	g.POST("/auth/list", h.Define("查看认证审计", "view_auth").
		Bind(ginx.B[ListAuthLogReq](h.ListAuthLogs)),
	)
	g.POST("/operation/list", h.Define("查看操作审计", "view_operation").
		Bind(ginx.B[ListOperationLogReq](h.ListOperationLogs)),
	)
}

// ListAuthLogs 分页查询认证审计日志
func (h *Handler) ListAuthLogs(ctx *ginx.Context, req ListAuthLogReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()

	filter := domain.AuthLogFilter{
		Username:  req.Username,
		AuthType:  req.AuthType,
		Status:    req.Status,
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
	}

	logs, total, err := h.svc.ListAuthLogs(reqCtx, filter, int(req.Offset), int(req.Limit))
	if err != nil {
		return ErrListAuthLogsFailed, err
	}

	items := lo.Map(logs, func(item domain.AuthLog, _ int) AuthLogVO {
		return toAuthLogVO(item)
	})

	return ginx.Result{
		Data: ListAuthLogResp{
			Total: total,
			List:  items,
		},
	}, nil
}

// ListOperationLogs 分页查询业务管理操作审计日志
func (h *Handler) ListOperationLogs(ctx *ginx.Context, req ListOperationLogReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()

	filter := domain.OperationLogFilter{
		Service:      req.Service,
		Module:       req.Module,
		Action:       req.Action,
		Status:       req.Status,
		OperatorName: req.OperatorName,
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
	}

	logs, total, err := h.svc.ListOperationLogs(reqCtx, filter, int(req.Offset), int(req.Limit))
	if err != nil {
		return ErrListOperationLogsFailed, err
	}

	items := lo.Map(logs, func(item domain.OperationLog, _ int) OperationLogVO {
		return toOperationLogVO(item)
	})

	return ginx.Result{
		Data: ListOperationLogResp{
			Total: total,
			List:  items,
		},
	}, nil
}
