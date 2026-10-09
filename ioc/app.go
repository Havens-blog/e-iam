package ioc

import (
	"context"

	"github.com/Havens-blog/e-iam/internal/grpcx"
	"github.com/Havens-blog/e-iam/internal/service/resource"
	"github.com/Havens-blog/e-iam/pkg/web/capability"
	"github.com/gotomicro/ego/server/egin"
)

// App 核心应用容器
type App struct {
	// Web 容器组件
	Web *egin.Component
	// GRPC 服务组件
	Server *grpcx.Server
	// Init 资产初始化器
	Init resource.IInitializer
	// Providers 权限能力供应者清单
	Providers []capability.PermissionProvider
	// Tasks 调度任务清单
	Tasks []Task
}

// Task 调度平台上的长任务 —— 各种补偿任务、消费者等
type Task interface {
	Start(ctx context.Context)
}
