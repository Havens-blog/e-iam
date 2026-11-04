package cryptox

// EncryptedPrefix 全局前缀
const EncryptedPrefix = "ENC:"

// ICrypto 定义通用加密解密接口
type ICrypto interface {
	// Encrypt 加密数据
	Encrypt(plainText string) (string, error)

	// Decrypt 解密数据
	Decrypt(encryptedText string) (string, error)
}
