package discovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Havens-blog/e-iam/internal/cryptox"
	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
)

const discoveryTokenPrefix = "discovery:service:"

// ITokenService 微服务资产自发现专属令牌管理服务
type ITokenService interface {
	// GenerateToken 为指定微服务生成专属资产自发现令牌 (Service Discovery Token, eiam_sct_...)
	GenerateToken(ctx context.Context, serviceName string) (string, error)

	// VerifyToken 校验微服务专属令牌并返回绑定的微服务标识
	VerifyToken(ctx context.Context, token string) (string, error)
}

type tokenService struct {
	tenantKeyRepo repository.ITenantKeyRepository
	serviceRepo   repository.IServiceRepository
}

// NewTokenService 构建微服务资产自发现专属令牌服务 (轻量纯 DB 依赖，供 CLI 及 Handler 复用)
func NewTokenService(
	tenantKeyRepo repository.ITenantKeyRepository,
	serviceRepo repository.IServiceRepository,
) ITokenService {
	return &tokenService{
		tenantKeyRepo: tenantKeyRepo,
		serviceRepo:   serviceRepo,
	}
}

// GenerateToken 为指定微服务生成专属资产自发现令牌 (绑定系统租户 tenant_id=1)。
// 生成前会前置校验微服务在服务目录中已登记，防止随意生成无效服务名。
func (s *tokenService) GenerateToken(ctx context.Context, serviceName string) (string, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "", fmt.Errorf("微服务标识不能为空")
	}

	//  资产发现令牌归属于系统根租户
	ctx = ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)

	// 前置校验：服务 code 必须在服务目录中已登记
	if _, err := s.serviceRepo.GetByCode(ctx, serviceName); err != nil {
		return "", fmt.Errorf("微服务 [%s] 在服务目录中不存在，请先完成注册: %w", serviceName, err)
	}

	randomPart, err := generateRandomHex(32)
	if err != nil {
		return "", fmt.Errorf("生成随机令牌失败: %w", err)
	}

	token := "eiam_sct_" + randomPart

	// 存入系统租户名下，description 标记服务绑定关系。
	// AccessKey 落库前做 SHA-256 哈希：资产发现令牌为单值 bearer（AccessKey==令牌），
	// 明文落库会使 DB 只读泄露即等于全部微服务发现令牌泄露；存哈希后即便泄露也无法逆推 256 位原值。
	// 明文令牌仅在生成时返回一次，校验时由调用方传入再哈希比对。
	tk := domain.TenantKey{
		TenantID:    ctxutil.SystemTenantID,
		AccessKey:   cryptox.HashSecret(token),
		SecretKey:   "",
		Status:      1, // 启用
		Description: fmt.Sprintf("%s%s", discoveryTokenPrefix, serviceName),
	}

	if _, err := s.tenantKeyRepo.Create(ctx, tk); err != nil {
		return "", fmt.Errorf("保存微服务令牌失败: %w", err)
	}

	return token, nil
}

// VerifyToken 校验微服务专属令牌并返回其绑定的微服务标识
func (s *tokenService) VerifyToken(ctx context.Context, token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errs.ErrInvalidToken
	}

	// 新记录 AccessKey 存哈希，按哈希查表；历史明文令牌按原值查表（平滑迁移期）。
	tk, err := s.tenantKeyRepo.FindByAccessKey(ctx, cryptox.HashSecret(token))
	if err != nil {
		// 回退明文查表：兼容迁移前已落库的明文令牌。
		tk, err = s.tenantKeyRepo.FindByAccessKey(ctx, token)
		if err != nil {
			return "", errs.ErrInvalidToken
		}
		// 历史明文令牌命中时以恒定时间确认原值（防明文表弱化时序侧信道）。
		if subtle.ConstantTimeCompare([]byte(tk.AccessKey), []byte(token)) != 1 {
			return "", errs.ErrInvalidToken
		}
	}

	if tk.Status != 1 {
		return "", errs.ErrTenantKeyDisabled
	}

	if !strings.HasPrefix(tk.Description, discoveryTokenPrefix) {
		return "", fmt.Errorf("凭据未绑定资产发现服务标识")
	}

	serviceName := strings.TrimPrefix(tk.Description, discoveryTokenPrefix)
	return serviceName, nil
}

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
