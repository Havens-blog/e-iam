//go:build wireinject

package testioc

import (
	"github.com/Havens-blog/e-iam/internal/pkg/searcher"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/repository/cache"
	"github.com/Havens-blog/e-iam/internal/repository/dao"
	"github.com/Havens-blog/e-iam/internal/service/permission"
	"github.com/Havens-blog/e-iam/internal/service/permission/checker"
	policysvc "github.com/Havens-blog/e-iam/internal/service/policy"
	"github.com/Havens-blog/e-iam/internal/service/resource"
	"github.com/Havens-blog/e-iam/internal/service/role"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	mainioc "github.com/Havens-blog/e-iam/ioc"
	"github.com/google/wire"
)

// ProvideTestSubjectRegistry 提供测试环境下空的主体注册中心
func ProvideTestSubjectRegistry() searcher.ISubjectRegistry {
	return searcher.NewSubjectRegistry()
}

func InitPermissionSuiteDeps() (*PermissionSuiteDeps, error) {
	wire.Build(
		// 基础组件：使用 testioc 本地定义的 InitDB (跳过 goose 迁移)
		InitDB,
		mainioc.InitRedis,
		mainioc.InitCasbin,
		mainioc.InitOPA,
		ProvideTestSubjectRegistry,

		// Cache
		cache.NewUserCache,
		cache.NewResourceCache,
		cache.NewPermissionCache,

		// DAOs
		dao.NewTenantDAO,
		dao.NewTenantKeyDAO,
		dao.NewRoleDAO,
		dao.NewResourceDAO,
		dao.NewPermissionDAO,
		dao.NewPolicyDAO,
		dao.NewServiceDAO,
		dao.NewUserDAO,

		// Repositories
		repository.NewTenantRepository,
		repository.NewTenantKeyRepository,
		repository.NewRoleRepository,
		repository.NewResourceRepository,
		repository.NewPermissionRepository,
		repository.NewPolicyRepository,
		repository.NewServiceRepository,
		repository.NewUserRepository,

		// Services
		role.NewRoleService,
		resource.NewResourceService,
		permission.NewPermissionService,
		policysvc.NewPolicyService,
		checker.NewBoundaryChecker,
		tenant.NewTenantService,
		tenant.NewTenantKeyService,

		// 组装返回结构
		wire.Struct(new(PermissionSuiteDeps), "*"),
	)
	return new(PermissionSuiteDeps), nil
}
