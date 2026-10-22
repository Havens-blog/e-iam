package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	testioc "github.com/Havens-blog/e-iam/internal/test/ioc"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type TenantKeySuite struct {
	suite.Suite
	db        *gorm.DB
	tenantSvc tenant.ITenantService
	keySvc    tenant.ITenantKeyService
}

func (s *TenantKeySuite) SetupSuite() {
	dir, _ := os.Getwd()
	cfgPath := filepath.Join(dir, "../config/config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		s.T().Skipf("跳过集成测试：缺少 %s（复制 config.example.yaml 并配置真实测试 MySQL/Redis）", cfgPath)
		return
	}
	viper.SetConfigFile(cfgPath)
	_ = viper.ReadInConfig()

	deps, _ := testioc.InitPermissionSuiteDeps()
	s.db = deps.DB
	s.tenantSvc = deps.TenantSvc
	s.keySvc = deps.TenantKeySvc
}

func (s *TenantKeySuite) TearDownTest() {
	s.clearAll()
}

func (s *TenantKeySuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `membership`")
	s.db.Exec("DELETE FROM `tenant_key`")
}

func (s *TenantKeySuite) TestTenantKey_Lifecycle() {
	ctx := context.Background()

	// 1. 创建租户并验证是否自动生成了 API Key
	tenantID, err := s.tenantSvc.CreateTenant(ctx, domain.Tenant{Name: "测试租户", Code: "test-tenant"}, "owner_user", 1001)
	s.NoError(err)
	s.True(tenantID > 0)

	// 1.1 显式生成一枚凭证，捕获明文 SK 用于后续 VerifyKey 校验
	// （CreateTenant 自动生成的凭证明文不会返回；安全改造后落库的是哈希）
	genKey, err := s.keySvc.GenerateKey(ctx, tenantID, "测试凭证2")
	s.NoError(err)
	s.True(genKey.ID > 0)
	s.Len(genKey.SecretKey, 48) // 明文 SK 仅生成时返回，48 字节十六进制

	// 2. 列表查询凭证，断言包含刚才生成的 Key，且落库 SecretKey 为哈希（非明文）
	keys, err := s.keySvc.ListKeysByTenantID(ctx, tenantID)
	s.NoError(err)
	s.GreaterOrEqual(len(keys), 2)

	var stored domain.TenantKey
	for _, k := range keys {
		if k.ID == genKey.ID {
			stored = k
		}
	}
	s.Equal(tenantID, stored.TenantID)
	s.True(strings.HasPrefix(stored.AccessKey, "AK"))
	s.Len(stored.AccessKey, 26)                    // "AK" (2字节) + 24字节十六进制 = 26 长度
	s.Len(stored.SecretKey, 64)                    // 落库为 SHA-256 哈希（64 十六进制），非明文
	s.NotEqual(stored.SecretKey, genKey.SecretKey) // 落库哈希 ≠ 明文
	s.Equal(1, stored.Status)                      // 默认是启用状态

	// 3. 校验能够通过 AccessKey 正确解析出 TenantID
	tid, err := s.keySvc.GetTenantIDByAccessKey(ctx, genKey.AccessKey)
	s.NoError(err)
	s.Equal(tenantID, tid)

	// 4. 校验 VerifyKey 方法（用生成时捕获的明文 SK）
	// 4.1 正确的凭证
	verifiedTid, err := s.keySvc.VerifyKey(ctx, genKey.AccessKey, genKey.SecretKey)
	s.NoError(err)
	s.Equal(tenantID, verifiedTid)

	// 4.2 错误的 SecretKey
	_, err = s.keySvc.VerifyKey(ctx, genKey.AccessKey, "wrong_secret")
	s.ErrorIs(err, errs.ErrInvalidTenantKey)

	// 5. 将该 Key 禁用，验证是否无法再解析出 TenantID
	// 调用方须携带租户上下文：UpdateKeyStatus 现强制按 tenant_id 归属过滤防跨租户操纵。
	err = s.keySvc.UpdateKeyStatus(ctxutil.WithTenantID(ctx, tenantID), genKey.ID, 0)
	s.NoError(err)

	_, err = s.keySvc.GetTenantIDByAccessKey(ctx, genKey.AccessKey)
	s.ErrorIs(err, errs.ErrTenantKeyDisabled)

	// 5.1 禁用的凭证进行 VerifyKey
	_, err = s.keySvc.VerifyKey(ctx, genKey.AccessKey, genKey.SecretKey)
	s.ErrorIs(err, errs.ErrTenantKeyDisabled)
}

func (s *TenantKeySuite) TestInitPersonalTenant_Lifecycle() {
	ctx := context.Background()

	// 1. 初始化个人空间并验证是否生成了凭证
	tenantID, err := s.tenantSvc.InitPersonalTenant(ctx, 1002, "personal_user")
	s.NoError(err)
	s.True(tenantID > 0)

	keys, err := s.keySvc.ListKeysByTenantID(ctx, tenantID)
	s.NoError(err)
	s.Len(keys, 1)

	key := keys[0]
	s.Equal(tenantID, key.TenantID)
	s.True(strings.HasPrefix(key.AccessKey, "AK"))
	s.Equal(1, key.Status)
}

func TestTenantKey(t *testing.T) {
	suite.Run(t, new(TenantKeySuite))
}
