// Command seedclient 注册服务间调用 (S2S) 客户端。
//
// 用于替代手动控制台注册:client_credentials 机密客户端应随部署代码化,
// 可重复、可审计、secret 由本命令生成且仅输出一次。
package seedclient

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Havens-blog/e-iam/internal/domain"
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/ioc"
	"github.com/spf13/cobra"
)

// NewCommand 返回 S2S 客户端注册子命令。
func NewCommand() *cobra.Command {
	var (
		clientID string
		name     string
		tenants  string
	)

	cmd := &cobra.Command{
		Use:   "seedclient",
		Short: "注册服务间调用 (S2S) 客户端",
		Long: `注册一个 client_credentials 机密客户端,用于服务间调用 (S2S)。

幂等:client_id 已存在时跳过注册,不重复生成密钥。
allowed_tenants: 逗号分隔的租户 ID 列表;-1 表示全租户通配 (仅平台核心服务)。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := ioc.InitSeedClientService()
			if err != nil {
				return fmt.Errorf("初始化应用服务失败: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// 幂等:已存在则跳过 (不重复注册、不泄露既有密钥)
			if existing, err := svc.GetByClientID(ctx, clientID); err == nil {
				fmt.Printf("client [%s] 已存在 (id=%d), 跳过注册\n", clientID, existing.ID)
				return nil
			} else if !errors.Is(err, errs.ErrApplicationNotFound) {
				return fmt.Errorf("查询 client 失败: %w", err)
			}

			allowedTenants, err := parseTenants(tenants)
			if err != nil {
				return err
			}

			if name == "" {
				name = clientID
			}

			created, err := svc.Create(ctx, domain.Application{
				Name:           name,
				ClientID:       clientID,
				RedirectURIs:   []string{"http://localhost/s2s"}, // client_credentials 用不到,但校验必填
				GrantTypes:     []string{"client_credentials"},
				AllowedTenants: allowedTenants,
				IsPublic:       false, // 机密客户端
			})
			if err != nil {
				return fmt.Errorf("注册客户端失败: %w", err)
			}

			fmt.Println("==============================================================")
			fmt.Printf("✔ S2S 客户端 [%s] 注册成功 (id=%d)\n", created.ClientID, created.ID)
			fmt.Println("==============================================================")
			fmt.Printf("client_id:       %s\n", created.ClientID)
			fmt.Printf("client_secret:   %s\n", created.ClientSecret)
			fmt.Printf("allowed_tenants: %v\n", allowedTenants)
			fmt.Println()
			fmt.Println("注意:client_secret 仅此一次显示,请妥善保管,并填入消费方配置。")
			fmt.Println("==============================================================")
			return nil
		},
	}

	cmd.Flags().StringVarP(&clientID, "client-id", "c", "", "客户端标识 (如 opsagent)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "应用显示名 (默认 = client-id)")
	cmd.Flags().StringVarP(&tenants, "tenants", "t", "-1", "允许代表的租户 ID 列表,逗号分隔;-1 = 全租户通配")
	_ = cmd.MarkFlagRequired("client-id")

	return cmd
}

// parseTenants 解析逗号分隔的租户 ID 列表。
func parseTenants(s string) ([]int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("allowed_tenants 不能为空")
	}
	parts := strings.Split(s, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("非法租户 ID: %q", p)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("allowed_tenants 不能为空")
	}
	return out, nil
}
