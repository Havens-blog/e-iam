package tenant

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"

	"github.com/Havens-blog/e-iam/internal/cryptox"
	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
)

// ITenantKeyService 租户密钥管理服务：提供租户凭证的生命周期管理与有效性校验
type ITenantKeyService interface {
	// GenerateKey 为指定租户随机生成一对鉴权凭证（AccessKey/SecretKey）
	GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error)
	// GetTenantIDByAccessKey 根据 AccessKey 快速查询租户 ID，用于租户有效性前置判定
	GetTenantIDByAccessKey(ctx context.Context, ak string) (int64, error)
	// VerifyKey 双重校验 AccessKey 与 SecretKey，用于第三方 API 调用的安全鉴权与身份识别
	VerifyKey(ctx context.Context, ak, sk string) (int64, error)
	// ListKeysByTenantID 检索指定租户下拥有的所有凭证列表，支持多凭证管理与轮转过渡
	ListKeysByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error)
	// UpdateKeyStatus 启用或禁用指定的凭证，用于密钥泄露时的紧急停用或状态管理
	UpdateKeyStatus(ctx context.Context, id int64, status int) error
}

type tenantKeyService struct {
	repo repository.ITenantKeyRepository
}

func NewTenantKeyService(r repository.ITenantKeyRepository) ITenantKeyService {
	return &tenantKeyService{repo: r}
}

func (s *tenantKeyService) GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error) {
	ak, err := generateRandomHex(24)
	if err != nil {
		return domain.TenantKey{}, err
	}
	// 加个 AK 前缀以作标识，比如 AKc58f...
	accessKey := "AK" + ak

	sk, err := generateRandomHex(48)
	if err != nil {
		return domain.TenantKey{}, err
	}

	tk := domain.TenantKey{
		TenantID:    tenantID,
		AccessKey:   accessKey,
		// SecretKey 落库前做 SHA-256 哈希：DB 只读泄露时无法逆推 192 位随机原值，
		// 明文 SK 仅在生成时返回一次（domain.SecretKey 已 json:"-" 隐藏于后续响应）。
		SecretKey:   cryptox.HashSecret(sk),
		Status:      1, // 默认启用
		Description: description,
	}

	id, err := s.repo.Create(ctx, tk)
	if err != nil {
		return domain.TenantKey{}, err
	}
	tk.ID = id
	// 返回给调用方的 SecretKey 保持明文（仅此一次展示），落库的是哈希。
	tk.SecretKey = sk
	return tk, nil
}

func (s *tenantKeyService) GetTenantIDByAccessKey(ctx context.Context, ak string) (int64, error) {
	tk, err := s.repo.FindByAccessKey(ctx, ak)
	if err != nil {
		return 0, err
	}
	// 如果凭证已被禁用，则不能用于鉴权和获取租户 ID
	if tk.Status != 1 {
		return 0, errs.ErrTenantKeyDisabled
	}
	return tk.TenantID, nil
}

func (s *tenantKeyService) VerifyKey(ctx context.Context, ak, sk string) (int64, error) {
	tk, err := s.repo.FindByAccessKey(ctx, ak)
	if err != nil {
		return 0, err
	}
	if tk.Status != 1 {
		return 0, errs.ErrTenantKeyDisabled
	}
	// 恒定时间比较：防止时序侧信道逐字节探测出 secret_key。
	// 双轨兼容：新记录存 SHA-256 哈希，历史明文记录平滑迁移期内一并支持，
	// 迁移完成后可移除明文分支。
	providedHash := cryptox.HashSecret(sk)
	if subtle.ConstantTimeCompare([]byte(providedHash), []byte(tk.SecretKey)) == 1 {
		return tk.TenantID, nil
	}
	if cryptox.IsHashedSecret(tk.SecretKey) {
		// 存储值已是哈希但与输入哈希不匹配，判失败。
		return 0, errs.ErrInvalidTenantKey
	}
	// 历史明文记录：恒定时间比较明文。
	if subtle.ConstantTimeCompare([]byte(tk.SecretKey), []byte(sk)) != 1 {
		return 0, errs.ErrInvalidTenantKey
	}
	return tk.TenantID, nil
}

func (s *tenantKeyService) ListKeysByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error) {
	return s.repo.ListByTenantID(ctx, tenantID)
}

func (s *tenantKeyService) UpdateKeyStatus(ctx context.Context, id int64, status int) error {
	// tenant_key 表整体 eiam:"ignore"，租户插件不会注入归属过滤。
	// 此处从上下文取调用方 tenant_id 一并下推 DAO，确保只能改本租户凭证，
	// 防止凭猜测 ID 跨租户禁用/启用他租户密钥（DoS / 配合社工）。
	tenantID := ctxutil.GetTenantID(ctx).Int64()
	return s.repo.UpdateStatus(ctx, id, tenantID, status)
}

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
