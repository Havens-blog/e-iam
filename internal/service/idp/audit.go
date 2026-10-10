package idp

import (
	"context"
	"time"

	"github.com/Havens-blog/e-iam/internal/domain"
	auditevt "github.com/Havens-blog/e-iam/internal/event/audit"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/gotomicro/ego/core/elog"
)

// RecordAudit 异步记录 IDP 域操作审计日志
func RecordAudit(ctx context.Context, p auditevt.IAuditProducer, tenantID int64, action, resourceID, resourceName, status, failReason string) {
	if p == nil {
		return
	}

	// 提前在主上下文提取客户端信息，避免异步协程产生上下文生命周期竞争
	clientIP := ctxutil.GetClientIP(ctx)
	userAgent := ctxutil.GetUserAgent(ctx)

	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := p.RecordOperation(asyncCtx, domain.OperationLog{
			TenantID:     tenantID,
			Service:      "iam",
			Module:       "idp",
			Action:       action,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			Status:       status,
			FailReason:   failReason,
			ClientIP:     clientIP,
			UserAgent:    userAgent,
			Ctime:        time.Now().UnixMilli(),
		}); err != nil {
			// 审计是 fire-and-forget，但失败应可见：静默吞错会让审计链路断裂长期无感
			elog.DefaultLogger.Warn("IDP 审计异步记录失败", elog.FieldErr(err), elog.String("action", action))
		}
	}()
}
