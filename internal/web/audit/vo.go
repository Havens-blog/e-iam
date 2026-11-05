package audit

import "github.com/Havens-blog/e-iam/internal/domain"

// ListAuthLogReq 认证审计日志查询入参
type ListAuthLogReq struct {
	Offset    int64  `json:"offset"`
	Limit     int64  `json:"limit"`
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"`
	Status    string `json:"status"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
}

// AuthLogVO 认证审计日志前端展示对象
type AuthLogVO struct {
	ID         int64  `json:"id"`
	TenantID   int64  `json:"tenant_id"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
	AuthType   string `json:"auth_type"`
	Status     string `json:"status"`
	FailReason string `json:"fail_reason"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Ctime      int64  `json:"ctime"`
}

// ListAuthLogResp 认证审计日志查询结果
type ListAuthLogResp struct {
	Total int64       `json:"total"`
	List  []AuthLogVO `json:"list"`
}

// ListOperationLogReq 操作审计日志查询入参 (严格对齐前端检索面板)
type ListOperationLogReq struct {
	Offset       int64  `json:"offset"`
	Limit        int64  `json:"limit"`
	Service      string `json:"service"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	OperatorName string `json:"operator_name"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
}

// OperationLogVO 操作审计日志前端展示对象
type OperationLogVO struct {
	ID           int64  `json:"id"`
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"`
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceURN  string `json:"resource_urn"`
	BeforeState  string `json:"before_state"`
	AfterState   string `json:"after_state"`
	Status       string `json:"status"`
	FailReason   string `json:"fail_reason"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"`
}

// ListOperationLogResp 操作审计日志查询结果
type ListOperationLogResp struct {
	Total int64            `json:"total"`
	List  []OperationLogVO `json:"list"`
}

// ListAuditEventsReq 统一审计事件查询入参。
// 服务端强制租户上下文（gormx fail-closed），入参不含 tenant_id。
type ListAuditEventsReq struct {
	Offset       int64  `json:"offset"`
	Limit        int64  `json:"limit"`
	Service      string `json:"service"`
	Domain       string `json:"domain"`
	Action       string `json:"action"`
	Result       string `json:"result"`
	ActorID      string `json:"actor_id"`
	ResourceType string `json:"resource_type"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
}

// AuditEventVO 统一审计事件前端展示对象
type AuditEventVO struct {
	ID           int64  `json:"id"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	ActorName    string `json:"actor_name"`
	At           int64  `json:"at"`
	TenantID     int64  `json:"tenant_id"`
	ClientIP     string `json:"client_ip"`
	Service      string `json:"service"`
	Domain       string `json:"domain"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	ResourceURN  string `json:"resource_urn"`
	Result       string `json:"result"`
	StatusCode   int    `json:"status_code"`
	DurationMs   int64  `json:"duration_ms"`
	Detail       string `json:"detail"`
}

// ListAuditEventsResp 统一审计事件查询结果
type ListAuditEventsResp struct {
	Total int64          `json:"total"`
	List  []AuditEventVO `json:"list"`
}

func toAuditEventVO(e domain.UnifiedAuditEvent) AuditEventVO {
	return AuditEventVO{
		ID:        e.ID,
		ActorType: e.ActorType,
		ActorID:   e.ActorID,
		ActorName: e.ActorName,
		At:        e.At,
		TenantID:  e.TenantID,
		ClientIP:  e.ClientIP,
		Service:   e.Service,
		Domain:    e.Domain,
		Action:    e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		ResourceURN:  e.ResourceURN,
		Result:    e.Result,
		StatusCode: e.StatusCode,
		DurationMs:  e.DurationMs,
		Detail:    e.Detail,
	}
}

func toAuthLogVO(l domain.AuthLog) AuthLogVO {
	return AuthLogVO{
		ID:         l.ID,
		TenantID:   l.TenantID,
		UserID:     l.UserID,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIP:   l.ClientIP,
		UserAgent:  l.UserAgent,
		Ctime:      l.Ctime,
	}
}

func toOperationLogVO(l domain.OperationLog) OperationLogVO {
	return OperationLogVO{
		ID:           l.ID,
		TenantID:     l.TenantID,
		Service:      l.Service,
		OperatorID:   l.OperatorID,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceID:   l.ResourceID,
		ResourceName: l.ResourceName,
		ResourceURN:  l.ResourceURN,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIP:     l.ClientIP,
		UserAgent:    l.UserAgent,
		Ctime:        l.Ctime,
	}
}

// BatchOperationReq 微服务 SDK 批量上报操作审计载荷
type BatchOperationReq struct {
	Records []OperationLogRecord `json:"records"`
}

// OperationLogRecord 单条操作审计明细
type OperationLogRecord struct {
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"`
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceURN  string `json:"resource_urn"`
	AfterState   string `json:"after_state"`
	Status       string `json:"status"`
	FailReason   string `json:"fail_reason"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"`
}
