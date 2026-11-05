package domain

// UnifiedAuditEvent 统一审计事件领域对象（与 e-common-go/auditlog.AuditEvent 的
// envelope 契约一致：Who/When/Where/What/Result）。
//
// 为什么不直接复用 SDK 类型：SDK 属公共库，Domain 层（本包）严禁依赖持久化框架，
// 且 IAM 侧需要保持领域模型自治（e-cam 侧事件经联邦拉取后亦映射到此类型）。
type UnifiedAuditEvent struct {
	ID           int64  `json:"id"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	ActorName    string `json:"actor_name"`
	At           int64  `json:"at"`
	TenantID     int64  `json:"tenant_id"`
	ClientIP     string `json:"client_ip,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	Service      string `json:"service"`
	Domain       string `json:"domain"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id,omitempty"`
	ResourceURN  string `json:"resource_urn,omitempty"`
	Result       string `json:"result"`
	StatusCode   int    `json:"status_code,omitempty"`
	DurationMs   int64  `json:"duration_ms,omitempty"`
	Detail       string `json:"detail,omitempty"` // JSON 文本（写入前已经 SDK Sanitize）
	DedupKey     string `json:"dedup_key,omitempty"`
}

// UnifiedAuditEventFilter 统一审计事件检索过滤条件。
//
// 租户维度不在过滤条件里：gormx 对多租户表 fail-closed 自动注入租户上下文，
// 显式携带 tenant_id 反而给越权留口子（P0 #5 的教训——e-cam 侧查询参数伪造已拦）。
type UnifiedAuditEventFilter struct {
	Service      string
	Domain       string
	Action       string
	Result       string
	ActorID      string
	ResourceType string
	StartTime    int64 // Unix 毫秒；0 = 不限
	EndTime      int64 // Unix 毫秒；0 = 不限
}
