package testioc

import (
	"github.com/Havens-blog/e-iam/internal/service/permission"
	"github.com/Havens-blog/e-iam/internal/service/policy"
	"github.com/Havens-blog/e-iam/internal/service/resource"
	"github.com/Havens-blog/e-iam/internal/service/role"
	"github.com/Havens-blog/e-iam/internal/service/tenant"
	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

type PermissionSuiteDeps struct {
	DB          *gorm.DB
	Enforcer    *casbin.SyncedEnforcer
	TenantSvc   tenant.ITenantService
	TenantKeySvc tenant.ITenantKeyService
	RoleSvc     role.IRoleService
	PolicySvc   policy.IPolicyService
	ResourceSvc resource.IResourceService
	PermSvc     permission.IPermissionService
}
