// Command resetsecret 轮换 S2S 客户端密钥。
//
// 为什么需要它：seedclient 是幂等注册——client_id 已存在即跳过、不泄露既有密钥，
// 这保证了注册可重复执行，但也意味着**密钥泄露后没有现成的轮换入口**。
// 本命令补上这一环：按 client_id 定位应用，调用 ResetSecret 生成新密钥
// （旧密钥立即失效），新密钥仅此一次输出。
//
// 安全约定：新密钥只在标准输出打印一次，调用方应直接写入受保护配置并轮转日志，
// 避免明文落盘到终端回显、截图或会话记录。
package resetsecret

import (
	"context"
	"fmt"
	"time"

	"github.com/Havens-blog/e-iam/internal/repository"
	"github.com/Havens-blog/e-iam/internal/repository/cache"
	"github.com/Havens-blog/e-iam/internal/repository/dao"
	"github.com/Havens-blog/e-iam/internal/service/idp"
	"github.com/Havens-blog/e-iam/ioc"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/spf13/cobra"
)

// NewCommand 返回 S2S 客户端密钥轮换子命令。
func NewCommand() *cobra.Command {
	var clientID string

	cmd := &cobra.Command{
		Use:   "resetsecret",
		Short: "轮换 S2S 客户端密钥（旧密钥立即失效，新密钥仅输出一次）",
		Long: `按 client_id 定位机密客户端并重置其密钥。

适用场景：client_secret 曾出现在终端回显、日志或会话记录中，需要立即作废旧值。
执行后旧密钥立即失效，必须同步更新所有消费方（如 e-cam-service 的 eiam 配置块）
并重启，否则其服务间调用会认证失败。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 为什么不复用 ioc.InitSeedClientService：它的 DI 树注入的是 NilOidcCache
			// （注册场景免 Redis 依赖），但 ResetSecret 的缓存清除在 Nil 缓存上是空操作——
			// 轮换后真实 Redis 里仍是旧客户端，旧密钥会"看起来还能用"，新密钥反而认证失败。
			// 轮换必须让缓存清除命中真实缓存，所以这里显式组装带真实 Redis 的依赖树。
			db := ioc.InitDBWithoutMigrate()
			cmdable := ioc.InitRedis()
			repo := repository.NewApplicationRepository(
				dao.NewApplicationDAO(db),
				cache.NewOidcCache(cmdable),
			)
			svc := idp.NewApplicationService(repo)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// S2S 客户端是平台级资源,归属系统租户(gormx 多租户插件要求写操作携带租户上下文)
			ctx = ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)

			app, err := svc.GetByClientID(ctx, clientID)
			if err != nil {
				return fmt.Errorf("查询 client 失败: %w", err)
			}

			newSecret, err := svc.ResetSecret(ctx, app.ID)
			if err != nil {
				return fmt.Errorf("轮换密钥失败: %w", err)
			}

			fmt.Println("==============================================================")
			fmt.Printf("✔ S2S 客户端 [%s] 密钥已轮换 (id=%d)\n", app.ClientID, app.ID)
			fmt.Println("==============================================================")
			fmt.Printf("client_id:            %s\n", app.ClientID)
			fmt.Printf("new client_secret:    %s\n", newSecret)
			fmt.Println()
			fmt.Println("注意:旧密钥已立即失效;新密钥仅此一次显示,请立即写入消费方配置并重启。")
			fmt.Println("==============================================================")
			return nil
		},
	}

	cmd.Flags().StringVarP(&clientID, "client-id", "c", "", "客户端标识 (如 e-cam-service)")
	_ = cmd.MarkFlagRequired("client-id")

	return cmd
}
