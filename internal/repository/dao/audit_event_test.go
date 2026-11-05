package dao

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-common-go/auditlog"
	"github.com/Havens-blog/e-iam/internal/domain"
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
		dk := "dedup-eiam-1"
		row := AuditEventRow{
			ActorType: string(auditlog.ActorTypeScheduler), ActorId: "sys",
			At: 1700000000000, TenantId: 3,
			Service: auditlog.ServiceIAM, Domain: auditlog.DomainOperation,
			Action: "sync", ResourceType: "user", Result: string(auditlog.ResultSuccess),
			DedupKey: &dk,
		}
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), []AuditEventRow{row}))
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), []AuditEventRow{row}))

		var count int64
		require.NoError(t, db.Model(&AuditEventRow{}).Where("dedup_key = ?", "dedup-eiam-1").Count(&count).Error)
		assert.Equal(t, int64(1), count, "重复 DedupKey 应幂等去重")
	})

	// 回归（#5 数据丢失 BUG）：MySQL/SQLite 唯一索引把空串当值，多条空 DedupKey
	// 互相冲突且被逐条降级静默跳过——只有指针化（空→NULL）才允许多条无键事件共存。
	t.Run("多条空 DedupKey 事件共存（#5 回归）", func(t *testing.T) {
		db := newTestDB(t)
		d := &auditDAO{db: db}
		rows := []AuditEventRow{
			{ActorType: "human", ActorId: "7", At: 1700000001000, TenantId: 3,
				Service: "eiam", Domain: "operation", Action: "create", ResourceType: "user", Result: "success"},
			{ActorType: "human", ActorId: "7", At: 1700000002000, TenantId: 3,
				Service: "eiam", Domain: "operation", Action: "update", ResourceType: "user", Result: "failed"},
			{ActorType: "system", ActorId: "t-1", At: 1700000003000, TenantId: 3,
				Service: "eiam", Domain: "change", Action: "update", ResourceType: "role", Result: "success"},
		}
		require.NoError(t, d.BatchInsertAuditEvents(context.Background(), rows))
		var count int64
		require.NoError(t, db.Model(&AuditEventRow{}).Count(&count).Error)
		assert.Equal(t, int64(3), count, "三条无去重键事件应全部落库（不得被空串唯一冲突吞掉）")
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

// ==================== ListAuditEvents 表驱动测试 ====================

func seedEvents(t *testing.T, d *auditDAO, rows []AuditEventRow) {
	t.Helper()
	require.NoError(t, d.BatchInsertAuditEvents(context.Background(), rows))
}

func TestListAuditEvents(t *testing.T) {
	seed := []AuditEventRow{
		{ActorType: "human", ActorId: "7", At: 1700000001000, TenantId: 3,
			Service: "eiam", Domain: "operation", Action: "create", ResourceType: "user", Result: "success"},
		{ActorType: "human", ActorId: "7", At: 1700000002000, TenantId: 3,
			Service: "eiam", Domain: "operation", Action: "update", ResourceType: "user", Result: "failed"},
		{ActorType: "system", ActorId: "task-1", At: 1700000003000, TenantId: 3,
			Service: "eiam", Domain: "change", Action: "update", ResourceType: "role", Result: "success"},
	}
	testCases := []struct {
		name      string
		filter    domain.UnifiedAuditEventFilter
		wantTotal int64
		wantFirst domain.UnifiedAuditEvent // 排序首位（at 降序）
	}{
		{
			name:      "无过滤 → 全量，at 降序",
			filter:    domain.UnifiedAuditEventFilter{},
			wantTotal: 3,
			wantFirst: domain.UnifiedAuditEvent{ID: 3, ActorID: "task-1", Action: "update", At: 1700000003000},
		},
		{
			name:      "按 domain 过滤",
			filter:    domain.UnifiedAuditEventFilter{Domain: "change"},
			wantTotal: 1,
			wantFirst: domain.UnifiedAuditEvent{ID: 3, Domain: "change"},
		},
		{
			name:      "按 result 过滤",
			filter:    domain.UnifiedAuditEventFilter{Result: "failed"},
			wantTotal: 1,
			wantFirst: domain.UnifiedAuditEvent{ID: 2, Result: "failed"},
		},
		{
			name:      "按时间窗过滤（start>首条）",
			filter:    domain.UnifiedAuditEventFilter{StartTime: 1700000001500},
			wantTotal: 2,
			wantFirst: domain.UnifiedAuditEvent{ID: 3, At: 1700000003000},
		},
		{
			name:      "组合过滤无命中 → 空列表",
			filter:    domain.UnifiedAuditEventFilter{Domain: "auth"},
			wantTotal: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			d := &auditDAO{db: db}
			seedEvents(t, d, seed)

			rows, total, err := d.ListAuditEvents(context.Background(), tc.filter, 0, 20)
			require.NoError(t, err)
			assert.Equal(t, tc.wantTotal, total)
			if tc.wantTotal == 0 {
				assert.Empty(t, rows)
				return
			}
			require.NotEmpty(t, rows)
			assert.Equal(t, tc.wantFirst.ID, rows[0].Id, "首位应为 at 最新的那条")
			// 降序：首条 at >= 次条 at
			for i := 1; i < len(rows); i++ {
				assert.GreaterOrEqual(t, rows[i-1].At, rows[i].At)
			}
		})
	}

	t.Run("分页 offset/limit", func(t *testing.T) {
		db := newTestDB(t)
		d := &auditDAO{db: db}
		seedEvents(t, d, seed)

		page2, total, err := d.ListAuditEvents(context.Background(), domain.UnifiedAuditEventFilter{}, 1, 1)
		require.NoError(t, err)
		assert.Equal(t, int64(3), total, "total 不随分页变化")
		require.Len(t, page2, 1)
		assert.Equal(t, int64(1700000002000), page2[0].At, "offset=1&limit=1 应取 at 次新的那条")
	})
}
