// Package grpcx 提供基于原生 google.golang.org/grpc 的轻量 server 包装，
// 实现 gotomicro/ego 的 server.Server 接口，使其可被 ego 框架托管。
// 不包含服务注册（etcd）与 bizid/tenant 拦截器，仅保留可选的 JWT 鉴权。
package grpcx

import (
	"context"
	"fmt"
	"net"

	"github.com/gotomicro/ego/core/constant"
	"github.com/gotomicro/ego/core/elog"
	"github.com/gotomicro/ego/server"
	"google.golang.org/grpc"
)

// ComponentName 日志组件名
const ComponentName = "grpc.server"

// ServerConfig gRPC server 配置。
// 去掉了 etask 的 ServiceId / AdvertiseAddr，eiam 不需要服务注册。
type ServerConfig struct {
	Name       string `mapstructure:"name"`        // 必填:服务名
	ListenAddr string `mapstructure:"listen_addr"` // 必填:绑定地址
	AuthToken  string `mapstructure:"auth_token"`  // 可选:JWT 鉴权密钥，为空则不启用鉴权
}

// Validate 验证配置
func (c *ServerConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("ServiceName 不能为空")
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("监听地址不能为空")
	}
	return nil
}

// Server 内嵌 *grpc.Server 并实现 ego server.Server 接口。
type Server struct {
	*grpc.Server

	config   ServerConfig
	listener net.Listener
	logger   *elog.Component
}

// ServerOption Server 配置选项
type ServerOption func(*Server)

// WithJWTAuth 启用 JWT 认证。
// 如果 authToken 为空，则不启用认证。
func WithJWTAuth(authToken string) ServerOption {
	return func(s *Server) {
		s.config.AuthToken = authToken
	}
}

// NewServer 创建 gRPC Server 实例。
// 当 AuthToken 非空时自动挂载 JWT 鉴权一元拦截器。
func NewServer(cfg ServerConfig, opts ...ServerOption) *Server {
	s := &Server{
		config: cfg,
		logger: elog.DefaultLogger.With(elog.FieldComponentName(ComponentName)),
	}

	// 1. 应用自定义配置选项
	for _, opt := range opts {
		opt(s)
	}

	// 2. 组装一元拦截器链
	var unaryInterceptors []grpc.UnaryServerInterceptor
	if s.config.AuthToken != "" {
		unaryInterceptors = append(unaryInterceptors,
			NewJwtAuth(s.config.AuthToken).JwtAuthInterceptor(),
		)
	}

	// 3. 创建 gRPC Server
	s.Server = grpc.NewServer(
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
	)

	return s
}

// 以下方法实现 ego server.Server 接口，使其可被 egoApp.Serve() 托管。

// Name 实现 server.Server 接口
func (s *Server) Name() string {
	return s.config.Name
}

// Init 实现 server.Server 接口
func (s *Server) Init() error {
	return nil
}

// Start 实现 server.Server 接口。
// 用 net.Listen 绑定端口并异步 grpc.Server.Serve，不进行任何服务注册。
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("监听端口失败: %w", err)
	}
	s.listener = listener

	// 异步启动 gRPC 服务
	go func() {
		if err = s.Server.Serve(listener); err != nil {
			s.logger.Error("gRPC 服务器错误", elog.FieldErr(err))
		}
	}()

	return nil
}

// Stop 实现 server.Server 接口
func (s *Server) Stop() error {
	s.logger.Info("停止 gRPC 服务器")
	s.Server.GracefulStop()
	return nil
}

// GracefulStop 实现 server.Server 接口
func (s *Server) GracefulStop(ctx context.Context) error {
	s.logger.Info("优雅停止 gRPC 服务器")
	s.Server.GracefulStop()
	return nil
}

// PackageName 实现 server.Server 接口
func (s *Server) PackageName() string {
	return ComponentName
}

// Info 实现 server.Server 接口
func (s *Server) Info() *server.ServiceInfo {
	info := server.ApplyOptions(
		server.WithName(s.config.Name),
		server.WithKind(constant.ServiceProvider),
		server.WithScheme("grpc"),
		server.WithAddress(s.config.ListenAddr),
	)

	// 判断服务是否健康（已开始监听即视为健康）
	info.Healthy = s.listener != nil
	return &info
}
