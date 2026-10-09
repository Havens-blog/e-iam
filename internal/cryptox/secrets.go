package cryptox

import "fmt"

// minSecretLen 密钥/令牌最小长度（字节）。AES-256 需要 32 字节密钥；
// JWT 签名密钥与 Session 加密密钥同等强度要求，统一 32 字节下限。
const minSecretLen = 32

// weakPlaceholders 配置示例占位符，生产环境必须替换为强随机值。
// 命中即拒绝启动——这些值若被误带入生产，等同裸奔。
var weakPlaceholders = map[string]string{
	"your-grpc-auth-token":         "grpc auth_token",
	"your-session-encrypt-key":     "session_encrypted_key",
	"your-identity-encryption-key": "identity encryption_key",
	"changeme":                     "占位符",
	"123456":                       "弱口令",
}

// ValidateSecret 校验密钥/令牌强度，拒绝空值、过短值与已知占位符。
// 启动期 fail-fast：避免弱密钥/示例值被误带入生产导致会话可伪造、
// gRPC 鉴权可绕过、身份凭据可解密等攻击面。
//
// 用法：cfg 解析后立即调用，如
//
//	if err := cryptox.ValidateSecret("session_encrypted_key", cfg.SessionEncryptedKey); err != nil {
//	    panic(err)
//	}
func ValidateSecret(name, secret string) error {
	if secret == "" {
		return fmt.Errorf("%s 不能为空", name)
	}
	if len(secret) < minSecretLen {
		return fmt.Errorf("%s 长度不足（要求 ≥%d 字节，当前 %d），请使用强随机值", name, minSecretLen, len(secret))
	}
	if reason, ok := weakPlaceholders[secret]; ok {
		return fmt.Errorf("%s 使用了示例/弱值（%s），请替换为强随机值", name, reason)
	}
	return nil
}
