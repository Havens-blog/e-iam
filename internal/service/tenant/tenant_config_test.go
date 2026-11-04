package tenant

import (
	"context"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configRBACModel 与生产 ioc/casbin.go 的 RBAC 模型保持一致（g = _, _, _），
// 仅用于本文件内构造内存 Casbin 引擎；独立命名避免与其他测试文件冲突。
const configRBACModel = `[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, "ANY") && r.obj == p.obj`

// newConfigEnforcer 构造内存版 SyncedEnforcer（关闭 AutoSave，避免触碰
// string adapter 的未实现方法）。
func newConfigEnforcer(t *testing.T) *casbin.SyncedEnforcer {
	t.Helper()
	m, err := model.NewModelFromString(configRBACModel)
	require.NoError(t, err)
	e, err := casbin.NewSyncedEnforcer(m, stringadapter.NewAdapter("# seed"))
	require.NoError(t, err)
	e.EnableAutoSave(false)
	return e
}

// configFakeRepo 是 ITenantRepository 的函数字段式替身，仅覆盖配置透传验证
// 所需的方法；独立命名保证本文件自包含可提交。
type configFakeRepo struct {
	repository.ITenantRepository
	createFn     func(ctx context.Context, t domain.Tenant) (int64, error)
	createBindFn func(ctx context.Context, userID int64) error
	updateFn     func(ctx context.Context, t domain.Tenant) error
	findByIdFn   func(ctx context.Context, id int64) (domain.Tenant, error)
}

func (f *configFakeRepo) Create(ctx context.Context, t domain.Tenant) (int64, error) {
	if f.createFn != nil {
		return f.createFn(ctx, t)
	}
	return 0, nil
}

func (f *configFakeRepo) CreateBind(ctx context.Context, userID int64) error {
	if f.createBindFn != nil {
		return f.createBindFn(ctx, userID)
	}
	return nil
}

func (f *configFakeRepo) Update(ctx context.Context, t domain.Tenant) error {
	if f.updateFn != nil {
		return f.updateFn(ctx, t)
	}
	return nil
}

func (f *configFakeRepo) FindById(ctx context.Context, id int64) (domain.Tenant, error) {
	if f.findByIdFn != nil {
		return f.findByIdFn(ctx, id)
	}
	return domain.Tenant{}, nil
}

var _ repository.ITenantRepository = (*configFakeRepo)(nil)

// configFakeKeySvc 是 ITenantKeyService 的函数字段式替身，仅覆盖 GenerateKey。
type configFakeKeySvc struct {
	ITenantKeyService
}

func (f *configFakeKeySvc) GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error) {
	return domain.TenantKey{}, nil
}

var _ ITenantKeyService = (*configFakeKeySvc)(nil)

// TestTenantService_CreateTenantConfigPassthrough 验证创建租户时三类配置
// 完整下传仓储，且创建入口强制新租户为活跃态（状态不接受外部注入）。
func TestTenantService_CreateTenantConfigPassthrough(t *testing.T) {
	testCases := []struct {
		name string
		in   domain.Tenant
	}{
		{
			name: "带全量配置创建",
			in: domain.Tenant{
				Name: "Acme", Code: "acme",
				MaxAccounts:    100,
				MaxUsers:       50,
				MaxUserGroups:  10,
				FeatureSwitch:  map[string]bool{"cdn": true, "waf": false},
				AllowedVendors: []string{"aliyun", "tencent"},
			},
		},
		{
			name: "零配置创建等价无限制语义",
			in:   domain.Tenant{Name: "Beta", Code: "beta"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &configFakeRepo{createFn: func(_ context.Context, ent domain.Tenant) (int64, error) {
				assert.Equal(t, tc.in.Name, ent.Name)
				assert.Equal(t, tc.in.Code, ent.Code)
				assert.Equal(t, tc.in.MaxAccounts, ent.MaxAccounts)
				assert.Equal(t, tc.in.MaxUsers, ent.MaxUsers)
				assert.Equal(t, tc.in.MaxUserGroups, ent.MaxUserGroups)
				assert.Equal(t, tc.in.FeatureSwitch, ent.FeatureSwitch)
				assert.Equal(t, tc.in.AllowedVendors, ent.AllowedVendors)
				// 创建入口必须强制活跃态，状态字段不允许经配置侧路注入
				assert.Equal(t, 1, ent.Status)
				return 5, nil
			}}
			svc := NewTenantService(repo, nil, nil, newConfigEnforcer(t), &configFakeKeySvc{})
			id, err := svc.CreateTenant(context.Background(), tc.in, "owner", 42)
			require.NoError(t, err)
			assert.Equal(t, int64(5), id)
		})
	}
}

// TestTenantService_ConfigReadWrite 验证更新与读取链路对三类配置的透传。
func TestTenantService_ConfigReadWrite(t *testing.T) {
	t.Run("Update 携带配置下传仓储", func(t *testing.T) {
		var captured domain.Tenant
		repo := &configFakeRepo{updateFn: func(_ context.Context, ent domain.Tenant) error {
			captured = ent
			return nil
		}}
		svc := NewTenantService(repo, nil, nil, nil, &configFakeKeySvc{})
		in := domain.Tenant{
			ID: 5, Name: "New", Code: "new",
			MaxAccounts:    100,
			MaxUsers:       50,
			MaxUserGroups:  10,
			FeatureSwitch:  map[string]bool{"cdn": true},
			AllowedVendors: []string{"aws"},
		}
		require.NoError(t, svc.Update(context.Background(), in))
		assert.Equal(t, in, captured)
	})

	t.Run("GetByID 读回配置", func(t *testing.T) {
		repo := &configFakeRepo{findByIdFn: func(_ context.Context, id int64) (domain.Tenant, error) {
			return domain.Tenant{
				ID:             id,
				MaxAccounts:    100,
				FeatureSwitch:  map[string]bool{"cdn": true},
				AllowedVendors: []string{"aliyun"},
			}, nil
		}}
		svc := NewTenantService(repo, nil, nil, nil, &configFakeKeySvc{})
		got, err := svc.GetByID(context.Background(), 9)
		require.NoError(t, err)
		assert.Equal(t, int64(100), got.MaxAccounts)
		assert.Equal(t, map[string]bool{"cdn": true}, got.FeatureSwitch)
		assert.Equal(t, []string{"aliyun"}, got.AllowedVendors)
	})
}
