package ioc

import (
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/repository/cache"
	"github.com/Havens-blog/e-iam/internal/repository/dao"
	idpsvc "github.com/Havens-blog/e-iam/internal/service/idp"
	"github.com/google/wire"
)

// SeedClientSet S2S 客户端注册 CLI 专用轻量 Provider 集合 (仅依赖 DB,无 Redis)。
var SeedClientSet = wire.NewSet(
	dao.NewApplicationDAO,
	InitNilOidcCache,
	repository.NewApplicationRepository,
	idpsvc.NewApplicationService,
)

// InitNilOidcCache 为 CLI 场景提供空缓存 (无 Redis 依赖),仓储层已 nil 安全。
func InitNilOidcCache() cache.IOidcCache {
	return nil
}
