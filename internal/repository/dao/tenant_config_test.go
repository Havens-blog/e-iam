package dao

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// setupConfigDB 建立独立的 sqlite 内存库并迁移租户表，专用于配置列的持久化验证。
func setupConfigDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Tenant{}))
	return db
}

// TestTenantDAO_ConfigRoundTrip 验证三类租户配置列（配额/功能开关/云厂商白名单）
// 在创建、读取、更新全链路上不丢字段。功能开关与白名单以 JSON 列存储，
// 序列化正确性只能靠真实 DB 往返验证，函数式替身无法覆盖。
func TestTenantDAO_ConfigRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		in   Tenant
	}{
		{
			name: "全量配置写入后读出一致",
			in: Tenant{
				Name: "Acme", Code: "acme", Status: 1,
				MaxAccounts:    100,
				MaxUsers:       50,
				MaxUserGroups:  10,
				FeatureSwitch:  map[string]bool{"cdn": true, "waf": false},
				AllowedVendors: []string{"aliyun", "tencent"},
			},
		},
		{
			name: "零值配置等价无限制语义且可正常持久化",
			in:   Tenant{Name: "Beta", Code: "beta", Status: 1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupConfigDB(t)
			d := NewTenantDAO(db)

			id, err := d.Create(context.Background(), tc.in)
			require.NoError(t, err)
			require.True(t, id > 0)

			got, err := d.FindById(context.Background(), id)
			require.NoError(t, err)
			assert.Equal(t, tc.in.MaxAccounts, got.MaxAccounts)
			assert.Equal(t, tc.in.MaxUsers, got.MaxUsers)
			assert.Equal(t, tc.in.MaxUserGroups, got.MaxUserGroups)
			if tc.in.FeatureSwitch == nil {
				assert.Empty(t, got.FeatureSwitch)
			} else {
				assert.Equal(t, tc.in.FeatureSwitch, got.FeatureSwitch)
			}
			assert.Equal(t, tc.in.AllowedVendors, got.AllowedVendors)

			// 更新路径必须把 JSON 列一并写回，否则配置改不动（可配置性契约）
			upd := got
			upd.MaxAccounts = 200
			upd.MaxUsers = 0
			upd.FeatureSwitch = map[string]bool{"cdn": true}
			upd.AllowedVendors = []string{"aws"}
			require.NoError(t, d.Update(context.Background(), upd))

			got2, err := d.FindById(context.Background(), id)
			require.NoError(t, err)
			assert.Equal(t, int64(200), got2.MaxAccounts)
			assert.Equal(t, int64(0), got2.MaxUsers)
			assert.Equal(t, map[string]bool{"cdn": true}, got2.FeatureSwitch)
			assert.Equal(t, []string{"aws"}, got2.AllowedVendors)
			// 基础列不因 Update 重构而丢失
			assert.Equal(t, tc.in.Name, got2.Name)
			assert.Equal(t, tc.in.Code, got2.Code)
		})
	}
}

// TestTenantDAO_LegacyRowDefaultSemantics 模拟存量租户行（配置列加入前已存在，
// 列值为 NULL）升级后的读取语义：配额 0=无限制、开关空、白名单空=全部允许。
func TestTenantDAO_LegacyRowDefaultSemantics(t *testing.T) {
	db := setupConfigDB(t)
	require.NoError(t, db.Exec(
		"INSERT INTO tenant (id, name, code, domain, status, ctime, utime) VALUES (1, 'Legacy', 'legacy', '', 1, 1, 1)",
	).Error)

	d := NewTenantDAO(db)
	got, err := d.FindById(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, "Legacy", got.Name)
	assert.Zero(t, got.MaxAccounts)
	assert.Zero(t, got.MaxUsers)
	assert.Zero(t, got.MaxUserGroups)
	assert.Empty(t, got.FeatureSwitch)
	assert.Empty(t, got.AllowedVendors)
}
