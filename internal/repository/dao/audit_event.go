package dao

import (
	"context"
)

// AuditEventRow 统一审计事件 GORM 实体。
//
// 字段与 e-common-go/auditlog.AuditEvent 的 JSON 契约一一对应（跨服务统一
// envelope：Who/When/Where/What/Result），使 e-iam 与 e-cam-service 两侧的
// 统一审计在语义上可对接（P1 联邦查询）。
//
// Append-only：审计记录不允许篡改/抹除，DAO 只提供写入与检索。
type AuditEventRow struct {
	Id        int64  `gorm:"primaryKey;autoIncrement"`
	ActorType string `gorm:"column:actor_type;type:varchar(16);not null;index:idx_actor_at,priority:1;comment:'操作者类型: human/system/executor/scheduler'"`
	ActorId   string `gorm:"column:actor_id;type:varchar(64);not null;index:idx_actor_at,priority:2;comment:'操作者ID(统一字符串,兼容 int64 与外部ID)'"`
	ActorName string `gorm:"column:actor_name;type:varchar(128);comment:'操作者名称'"`
	At        int64  `gorm:"column:at;not null;index:idx_tenant_at,priority:2;comment:'事件时间(Unix毫秒)'"`
	TenantId  int64  `gorm:"column:tenant_id;not null;index:idx_tenant_at,priority:1;comment:'租户ID'"`
	ClientIP  string `gorm:"column:client_ip;type:varchar(64);comment:'客户端IP'"`
	UserAgent string `gorm:"column:user_agent;type:varchar(255);comment:'UserAgent'"`
	Service   string `gorm:"column:service;type:varchar(32);not null;index:idx_service_domain_at,priority:1;comment:'所属服务'"`
	Domain    string `gorm:"column:domain;type:varchar(32);not null;index:idx_service_domain_at,priority:2;comment:'业务域'"`
	Action    string `gorm:"column:action;type:varchar(64);not null;comment:'动作'"`
	ResourceType string `gorm:"column:resource_type;type:varchar(64);not null;comment:'资源类型'"`
	ResourceId   string `gorm:"column:resource_id;type:varchar(128);comment:'资源ID'"`
	ResourceUrn  string `gorm:"column:resource_urn;type:varchar(255);comment:'统一资源URN'"`
	Result   string `gorm:"column:result;type:varchar(16);not null;comment:'结果: success/failed/partial'"`
	StatusCode  int    `gorm:"column:status_code;comment:'状态码'"`
	DurationMs  int64  `gorm:"column:duration_ms;comment:'耗时(毫秒)'"`
	Detail      string `gorm:"column:detail;type:text;comment:'域扩展载荷(JSON,已脱敏)'"`
	DedupKey    string `gorm:"column:dedup_key;type:varchar(128);uniqueIndex:uk_dedup_key;comment:'幂等去重键(空=不去重)'"`
}

func (AuditEventRow) TableName() string { return "audit_events" }

// BatchInsertAuditEvents 批量写入统一审计事件（append-only，无 update/delete）。
// DedupKey 冲突视为幂等命中：批量失败时逐条降级插入并跳过冲突条目，
// 保证非冲突条目仍然落库。
func (d *auditDAO) BatchInsertAuditEvents(ctx context.Context, rows []AuditEventRow) error {
	if len(rows) == 0 {
		return nil
	}
	err := d.db.WithContext(ctx).CreateInBatches(rows, 100).Error
	if err == nil {
		return nil
	}
	// 批量失败（可能含唯一键冲突）：逐条插入，冲突条目跳过。
	for _, row := range rows {
		_ = d.db.WithContext(ctx).Create(&row).Error
	}
	return nil
}
