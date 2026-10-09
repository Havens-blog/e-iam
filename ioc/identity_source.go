package ioc

import (
	"github.com/Havens-blog/e-iam/internal/cryptox"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/service/identity_source"
)

func InitIdentitySourceService(repo repository.IIdentitySourceRepository, cm *cryptox.CryptoManager) identity_source.IService {
	return identity_source.NewService(repo, identity_source.NewOidcService(), cm)
}
