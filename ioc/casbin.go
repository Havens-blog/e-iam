package ioc

import (
	"fmt"
	"time"

	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	defaultrolemanager "github.com/casbin/casbin/v2/rbac/default-role-manager"
	gormAdapter "github.com/casbin/gorm-adapter/v3"
	redisWatcher "github.com/casbin/redis-watcher/v2"
	"github.com/ecodeclub/ekit/retry"
	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

const (
	rbacModel = `[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, "ANY") && r.obj == p.obj`
)

// InitCasbin 初始化 Casbin SyncedEnforcer
func InitCasbin(casbinDB *gorm.DB) *casbin.SyncedEnforcer {
	adapter, err := gormAdapter.NewAdapterByDB(casbinDB)
	if err != nil {
		fmt.Printf("警告: 初始化 Casbin Adapter 失败: %v\n", err)
		return nil
	}

	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		fmt.Printf("警告: Casbin 模型解析失败: %v\n", err)
		return nil
	}

	type RedisConfig struct {
		Addr     string `mapstructure:"addr"`
		DB       int    `mapstructure:"db"`
		UserName string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}
	var cfg RedisConfig
	if err = viper.UnmarshalKey("casbin.redis", &cfg); err != nil {
		fmt.Printf("警告: 无法读取 Redis 配置: %v\n", err)
	}

	w, err := newRedisWatcherWithRetry(cfg.Addr, cfg.DB, cfg.Password)
	if err != nil {
		panic(err)
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		fmt.Printf("警告: Enforcer 初始化失败: %v\n", err)
		return nil
	}

	_ = enforcer.SetWatcher(w)
	_ = w.SetUpdateCallback(updateCallback)

	enforcer.EnableLog(false)
	if err = enforcer.LoadPolicy(); err != nil {
		panic(err)
	}

	enforcer.StartAutoLoadPolicy(time.Minute)

	// 核心配置 —— 全局域穿透逻辑
	// 当我们在某个租户 TID 下查找角色关系时，如果规则是定义在全局域 ctxutil.SystemTenantIDStr 下的，
	// 通过下述匹配函数，Casbin 会自动将 TID 匹配到 ctxutil.SystemTenantIDStr，从而实现全局继承关系的自动解析。
	enforcer.GetRoleManager().(*defaultrolemanager.RoleManager).AddDomainMatchingFunc("DomainMatch", func(d1, d2 string) bool {
		return d1 == d2 || d2 == ctxutil.SystemTenantIDStr
	})

	return enforcer
}

func updateCallback(rev string) {
	// 可选打印 rev
}

// newRedisWatcherWithRetry 建立 Casbin Redis watcher，带指数退避重试。
// 远程共享 Redis（106.52.187.69:6379）偶发瞬时 i/o timeout：NewWatcher 内部对
// sub/pub 两个 client 各 Ping 一次，任一 dial 失败即返回 error。若首连失败直接 panic，
// 一次瞬时抖动就会阻断整个服务启动。故与 InitDB 的 WaitForDBSetup 同款指数退避策略，
// 瞬断时自动重连而非崩溃；DialTimeout 收紧到 3s 以界定单次尝试耗时。
func newRedisWatcherWithRetry(addr string, db int, password string) (persist.Watcher, error) {
	const (
		maxInterval = 10 * time.Second
		maxRetries  = 10
	)
	strategy, err := retry.NewExponentialBackoffRetryStrategy(time.Second, maxInterval, maxRetries)
	if err != nil {
		return nil, err
	}
	for {
		w, werr := redisWatcher.NewWatcher(addr, redisWatcher.WatcherOptions{
			Options: redis.Options{
				DB:          db,
				Password:    password,
				DialTimeout: 3 * time.Second,
			},
			Channel: "/casbin",
		})
		if werr == nil {
			return w, nil
		}
		next, ok := strategy.Next()
		if !ok {
			return nil, werr
		}
		time.Sleep(next)
	}
}
