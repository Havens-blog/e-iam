package ioc

import (
	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/service/identity_source"
	"github.com/Havens-blog/e-iam/internal/service/user/ldap"
)

// InitCredentialProviders 显式返回系统支持的所有凭证身份源列表
func InitCredentialProviders(idsSvc identity_source.IService) []domain.CredentialProvider {
	return []domain.CredentialProvider{
		ldap.NewDynamicLdapProvider(idsSvc),
	}
}
