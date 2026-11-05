package dao

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-common-go/auditlog"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newTestDB sqlite 内存库（单测严禁直连外部资源，glebarez/sqlite 纯 Go 无 CGO）
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AuditOperationLog{}, &AuditEventRow{}))
	return db
}

// ==================== BatchInsertAuditEvents 表驱动测试 ====================

func TestBatchInsertAuditEvents(t *testing.T) {
	t.Run("批量写入并回读", func(t *testing.T) {
		db := newTestDB(t)
		d := &auditDAO{db: db}
		rows := []AuditEventRow{{
			ActorType: string(auditlog.ActorTypeHuman), ActorId: "7", ActorName: "ops",
			At: 1700000000000, TenantId: 3,
			Service: auditlog.ServiceIAM, Domain: auditlog.DomainOperation,
			Action: "create", ResourceType: "user", Result: string(auditlog.ResultSuccess),
		}}
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), rows))

		var got AuditEventRow
		require.NoError(t, db.First(&got).Error)
		assert.Equal(t, "e-iam", got.Service)
		assert.Equal(t, "operation", got.Domain)
		assert.Equal(t, "create", got.Action)
	})

	t.Run("DedupKey 幂等：重复写入不重复落库", func(t *testing.T) {
		db := newTestDB(t)
		d := &auditDAO{db: db}
		row := AuditEventRow{
			ActorType: string(auditlog.ActorTypeScheduler), ActorId: "sys",
			At: 1700000000000, TenantId: 3,
			Service: auditlog.ServiceIAM, Domain: auditlog.DomainOperation,
			Action: "sync", ResourceType: "user", Result: string(auditlog.ResultSuccess),
			DedupKey: "dedup-eiam-1",
		}
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), []AuditEventRow{row}))
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), []AuditEventRow{row}))

		var count int64
		require.NoError(t, db.Model(&AuditEventRow{}).Where("dedup_key = ?", "dedup-eiam-1").Count(&count).Error)
		assert.Equal(t, int64(1), count, "重复 DedupKey 应幂等去重")
	})

	t.Run("空批次为 no-op", func(t *testing.T) {
		db := newTestDB(t)
		d := &auditDAO{db: db}
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), nil))
		var count int64
		require.NoError(t, db.Model(&AuditEventRow{}).Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})
}
