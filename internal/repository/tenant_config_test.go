package repository

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/repository/dao"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configFakeDAO 是 ITenantDAO 的函数字段式替身，仅覆盖配置透传验证所需的三个方法。
// 独立于其他测试文件的替身，保证本文件自包含可提交。
type configFakeDAO struct {
	dao.ITenantDAO
	createFn   func(ctx context.Context, t dao.Tenant) (int64, error)
	updateFn   func(ctx context.Context, t dao.Tenant) error
	findByIdFn func(ctx context.Context, id int64) (dao.Tenant, error)
}

func (f *configFakeDAO) Create(ctx context.Context, t dao.Tenant) (int64, error) {
	if f.createFn != nil {
		return f.createFn(ctx, t)
	}
	return 0, nil
}

func (f *configFakeDAO) Update(ctx context.Context, t dao.Tenant) error {
	if f.updateFn != nil {
		return f.updateFn(ctx, t)
	}
	return nil
}

func (f *configFakeDAO) FindById(ctx context.Context, id int64) (dao.Tenant, error) {
	if f.findByIdFn != nil {
		return f.findByIdFn(ctx, id)
	}
	return dao.Tenant{}, nil
}

var _ dao.ITenantDAO = (*configFakeDAO)(nil)

// TestTenantRepository_ConfigConversion 表驱动验证转换层（toEntity/toDomain）
// 对三类配置字段的双向映射完整性——转换丢字段是透传链路最隐蔽的断裂点。
func TestTenantRepository_ConfigConversion(t *testing.T) {
	src := domain.Tenant{
		ID:             1,
		Name:           "Acme",
		Code:           "acme",
		MaxAccounts:    100,
		MaxUsers:       50,
		MaxUserGroups:  10,
		FeatureSwitch:  map[string]bool{"cdn": true, "waf": false},
		AllowedVendors: []string{"aliyun", "tencent"},
	}

	t.Run("toEntity 不丢配置字段", func(t *testing.T) {
		got := (&TenantRepository{}).toEntity(src)
		assert.Equal(t, src.MaxAccounts, got.MaxAccounts)
		assert.Equal(t, src.MaxUsers, got.MaxUsers)
		assert.Equal(t, src.MaxUserGroups, got.MaxUserGroups)
		assert.Equal(t, src.FeatureSwitch, got.FeatureSwitch)
		assert.Equal(t, src.AllowedVendors, got.AllowedVendors)
	})

	t.Run("toDomain 不丢配置字段", func(t *testing.T) {
		ent := dao.Tenant{
			ID: 1, Name: "Acme", Code: "acme",
			MaxAccounts:    100,
			MaxUsers:       50,
			MaxUserGroups:  10,
			FeatureSwitch:  map[string]bool{"cdn": true, "waf": false},
			AllowedVendors: []string{"aliyun", "tencent"},
		}
		got := (&TenantRepository{}).toDomain(ent)
		assert.Equal(t, ent.MaxAccounts, got.MaxAccounts)
		assert.Equal(t, ent.MaxUsers, got.MaxUsers)
		assert.Equal(t, ent.MaxUserGroups, got.MaxUserGroups)
		assert.Equal(t, ent.FeatureSwitch, got.FeatureSwitch)
		assert.Equal(t, ent.AllowedVendors, got.AllowedVendors)
	})

	t.Run("零值转换保持无限制语义", func(t *testing.T) {
		r := &TenantRepository{}
		ent := r.toEntity(domain.Tenant{Name: "empty"})
		assert.Zero(t, ent.MaxAccounts)
		assert.Nil(t, ent.FeatureSwitch)
		assert.Nil(t, ent.AllowedVendors)
		dm := r.toDomain(dao.Tenant{Name: "empty"})
		assert.Zero(t, dm.MaxAccounts)
		assert.Nil(t, dm.FeatureSwitch)
		assert.Nil(t, dm.AllowedVendors)
	})
}

// TestTenantRepository_ConfigPassthrough 验证仓储 CRUD 入口对三类配置的透传。
func TestTenantRepository_ConfigPassthrough(t *testing.T) {
	ctx := context.Background()

	t.Run("Create 携带配置下传 DAO", func(t *testing.T) {
		var captured dao.Tenant
		r := NewTenantRepository(&configFakeDAO{createFn: func(_ context.Context, t dao.Tenant) (int64, error) {
			captured = t
			return 7, nil
		}})
		id, err := r.Create(ctx, domain.Tenant{
			Name: "Acme", Code: "acme",
			MaxAccounts:    100,
			FeatureSwitch:  map[string]bool{"cdn": true},
			AllowedVendors: []string{"aliyun"},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(7), id)
		assert.Equal(t, int64(100), captured.MaxAccounts)
		assert.Equal(t, map[string]bool{"cdn": true}, captured.FeatureSwitch)
		assert.Equal(t, []string{"aliyun"}, captured.AllowedVendors)
	})

	t.Run("Update 携带配置下传 DAO", func(t *testing.T) {
		var captured dao.Tenant
		r := NewTenantRepository(&configFakeDAO{updateFn: func(_ context.Context, t dao.Tenant) error {
			captured = t
			return nil
		}})
		require.NoError(t, r.Update(ctx, domain.Tenant{
			ID: 5, Name: "New", Code: "new",
			MaxUsers:       20,
			FeatureSwitch:  map[string]bool{"waf": true},
			AllowedVendors: []string{"aws"},
		}))
		assert.Equal(t, int64(5), captured.ID)
		assert.Equal(t, int64(20), captured.MaxUsers)
		assert.Equal(t, map[string]bool{"waf": true}, captured.FeatureSwitch)
		assert.Equal(t, []string{"aws"}, captured.AllowedVendors)
	})

	t.Run("FindById 还原配置", func(t *testing.T) {
		r := NewTenantRepository(&configFakeDAO{findByIdFn: func(_ context.Context, id int64) (dao.Tenant, error) {
			return dao.Tenant{
				ID: id, Name: "Acme", Code: "acme",
				MaxUserGroups:  10,
				FeatureSwitch:  map[string]bool{"cdn": true},
				AllowedVendors: []string{"tencent"},
			}, nil
		}})
		got, err := r.FindById(ctx, 9)
		require.NoError(t, err)
		assert.Equal(t, int64(10), got.MaxUserGroups)
		assert.Equal(t, map[string]bool{"cdn": true}, got.FeatureSwitch)
		assert.Equal(t, []string{"tencent"}, got.AllowedVendors)
	})
}
