package cryptox

import "crypto/sha256"

// HashSecret 对高熵随机密钥（如 AK/SK、资产发现令牌）计算 SHA-256 摘要的十六进制表示，
// 用于落库前以哈希替代明文存储：即便数据库只读泄露，攻击者也无法逆推 192/256 位随机原值。
//
// 设计取舍：
//   - 不引入 per-row salt 列：原始密钥已是足够长度的高熵随机值（SK 192 位、令牌 256 位），
//     彩虹表/预查表对其无意义，故无需 salt 即可抵御原值还原；这避免了新增 DB 列与迁移成本。
//   - 校验路径仍使用 subtle.ConstantTimeCompare 比较摘要，避免时序侧信道。
//
// 注：对低熵口令（用户密码）应使用 bcrypt/argon2id，本函数仅适用于高熵密钥。
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// IsHashedSecret 粗略判定存储值是否已是哈希摘要（64 位十六进制），
// 用于校验路径在“哈希存储”与“历史明文”之间做双轨兼容，支持一次性平滑迁移。
func IsHashedSecret(stored string) bool {
	if len(stored) != 64 {
		return false
	}
	for i := 0; i < len(stored); i++ {
		c := stored[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
