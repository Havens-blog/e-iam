package repository

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/repository/dao"
	"github.com/Havens-blog/e-common-go/auditlog"
	"github.com/samber/lo"
)

// IAuditRepository 安全审计仓储接口 (专注于认证与操作审计领域对象的持久化与多维检索)
//
//go:generate mockgen -package=repomocks -destination=./mocks/audit.mock.go github.com/Havens-blog/e-iam/internal/repository IAuditRepository
type IAuditRepository interface {
	// BatchSaveAuthLogs 批量持久化认证审计领域实体
	BatchSaveAuthLogs(ctx context.Context, logs []domain.AuthLog) error
	// BatchSaveOperationLogs 批量持久化业务操作审计领域实体
	BatchSaveOperationLogs(ctx context.Context, logs []domain.OperationLog) error
	// ListAuthLogs 分页检索认证审计记录并转化为领域对象
	ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error)
	// ListOperationLogs 分页检索业务管理操作审计记录并转化为领域对象
	ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error)
}

type auditRepository struct {
	dao dao.IAuditDAO
}

// NewAuditRepository 构建纯粹的安全审计数据仓储实例
func NewAuditRepository(dao dao.IAuditDAO) IAuditRepository {
	return &auditRepository{
		dao: dao,
	}
}

func (r *auditRepository) BatchSaveAuthLogs(ctx context.Context, logs []domain.AuthLog) error {
	if len(logs) == 0 {
		return nil
	}
	daoLogs := lo.Map(logs, func(l domain.AuthLog, _ int) dao.AuditAuthLog {
		return r.toAuthDAO(l)
	})
	return r.dao.BatchInsertAuthLogs(ctx, daoLogs)
}

func (r *auditRepository) BatchSaveOperationLogs(ctx context.Context, logs []domain.OperationLog) error {
	if len(logs) == 0 {
		return nil
	}
	daoLogs := lo.Map(logs, func(l domain.OperationLog, _ int) dao.AuditOperationLog {
		return r.toOpDAO(l)
	})
	if err := r.dao.BatchInsertOperationLogs(ctx, daoLogs); err != nil {
		return err
	}
	// 统一审计事件双写（旁路）：同一批操作以统一 envelope 落 audit_events 表，
	// 与 e-cam-service 侧的统一审计对接（P1 联邦查询）。失败不影响旧存储主写入。
	return r.emitUnifiedEvents(ctx, logs)
}

// emitUnifiedEvents 把操作审计批量翻译为统一审计事件并写入。
// 映射口径：ActorType=human（中间件只拦截登录会话写操作）；Service=e-iam；
// Domain=operation；Action/Module 沿用既有语义；Before/After 状态与 FailReason
// 收进 Detail（统一 envelope 不为 IAM 管理操作单开列）。
func (r *auditRepository) emitUnifiedEvents(ctx context.Context, logs []domain.OperationLog) error {
	events := make([]auditlog.AuditEvent, 0, len(logs))
	for _, l := range logs {
		ev := toUnifiedEvent(l)
		if err := ev.Validate(); err != nil {
			// 骨架不完整的事件跳过（不静默写入残缺审计，也不阻塞其余事件）
			continue
		}
		ev.Sanitize()
		events = append(events, ev)
	}
	if len(events) == 0 {
		return nil
	}
	rows := lo.Map(events, func(ev auditlog.AuditEvent, _ int) dao.AuditEventRow {
		detail, _ := json.Marshal(ev.Detail)
		return dao.AuditEventRow{
			ActorType: string(ev.ActorType),
			ActorId:   ev.ActorID,
			ActorName: ev.ActorName,
			At:        ev.At,
			TenantId:  ev.TenantID,
			ClientIP:  ev.ClientIP,
			UserAgent: ev.UserAgent,
			Service:   ev.Service,
			Domain:    ev.Domain,
			Action:    ev.Action,
			ResourceType: ev.ResourceType,
			ResourceId:   ev.ResourceID,
			ResourceUrn:  ev.ResourceURN,
			Result:    string(ev.Result),
			StatusCode: ev.StatusCode,
			DurationMs:  ev.DurationMs,
			Detail:      string(detail),
			DedupKey:    ev.DedupKey,
		}
	})
	return r.dao.BatchInsertAuditEvents(ctx, rows)
}

// toUnifiedEvent 把 IAM 管理操作审计翻译为统一审计事件（纯函数，便于表驱动测试）。
// 旧口径 Status 是大写 SUCCESS/FAIL；统一 Result 用小写三态。
func toUnifiedEvent(l domain.OperationLog) auditlog.AuditEvent {
	ev := auditlog.AuditEvent{
		ActorType:    auditlog.ActorTypeHuman,
		ActorID:      strconv.FormatInt(l.OperatorID, 10),
		ActorName:    l.OperatorName,
		At:           l.Ctime,
		TenantID:     l.TenantID,
		ClientIP:     l.ClientIP,
		UserAgent:    l.UserAgent,
		Service:      auditlog.ServiceIAM,
		Domain:       auditlog.DomainOperation,
		Action:       l.Action,
		ResourceType: l.Module,
		ResourceID:   l.ResourceID,
		ResourceURN:  l.ResourceURN,
		StatusCode:   0,
		Detail: map[string]any{
			"module":        l.Module,
			"resource_name": l.ResourceName,
			"fail_reason":   l.FailReason,
			"before_state":  l.BeforeState,
			"after_state":   l.AfterState,
		},
	}
	if strings.EqualFold(l.Status, "SUCCESS") {
		ev.Result = auditlog.ResultSuccess
	} else {
		ev.Result = auditlog.ResultFailed
	}
	return ev
}

func (r *auditRepository) ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error) {
	daoLogs, total, err := r.dao.ListAuthLogs(ctx, filter, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	logs := lo.Map(daoLogs, func(l dao.AuditAuthLog, _ int) domain.AuthLog {
		return r.toAuthDomain(l)
	})
	return logs, total, nil
}

func (r *auditRepository) ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error) {
	daoLogs, total, err := r.dao.ListOperationLogs(ctx, filter, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	logs := lo.Map(daoLogs, func(l dao.AuditOperationLog, _ int) domain.OperationLog {
		return r.toOpDomain(l)
	})
	return logs, total, nil
}

func (r *auditRepository) toAuthDAO(l domain.AuthLog) dao.AuditAuthLog {
	ctime := l.Ctime
	if ctime <= 0 {
		ctime = time.Now().UnixMilli()
	}
	return dao.AuditAuthLog{
		Id:         l.ID,
		TenantId:   l.TenantID,
		UserId:     l.UserID,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIp:   l.ClientIP,
		UserAgent:  l.UserAgent,
		Ctime:      ctime,
	}
}

func (r *auditRepository) toAuthDomain(l dao.AuditAuthLog) domain.AuthLog {
	return domain.AuthLog{
		ID:         l.Id,
		TenantID:   l.TenantId,
		UserID:     l.UserId,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIP:   l.ClientIp,
		UserAgent:  l.UserAgent,
		Ctime:      l.Ctime,
	}
}

func (r *auditRepository) toOpDAO(l domain.OperationLog) dao.AuditOperationLog {
	ctime := l.Ctime
	if ctime <= 0 {
		ctime = time.Now().UnixMilli()
	}
	return dao.AuditOperationLog{
		Id:           l.ID,
		TenantId:     l.TenantID,
		Service:      l.Service,
		OperatorId:   l.OperatorID,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceId:   l.ResourceID,
		ResourceName: l.ResourceName,
		ResourceUrn:  l.ResourceURN,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIp:     l.ClientIP,
		UserAgent:    l.UserAgent,
		Ctime:        ctime,
	}
}

func (r *auditRepository) toOpDomain(l dao.AuditOperationLog) domain.OperationLog {
	return domain.OperationLog{
		ID:           l.Id,
		TenantID:     l.TenantId,
		Service:      l.Service,
		OperatorID:   l.OperatorId,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceID:   l.ResourceId,
		ResourceName: l.ResourceName,
		ResourceURN:  l.ResourceUrn,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIP:     l.ClientIp,
		UserAgent:    l.UserAgent,
		Ctime:        l.Ctime,
	}
}
