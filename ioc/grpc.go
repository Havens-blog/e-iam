package ioc

import (
	departmentv1 "github.com/Havens-blog/e-iam/api/proto/gen/eiam/department/v1"
	tenantv1 "github.com/Havens-blog/e-iam/api/proto/gen/eiam/tenant/v1"
	userv1 "github.com/Havens-blog/e-iam/api/proto/gen/eiam/user/v1"
	"github.com/Havens-blog/e-iam/internal/grpcx"

	"github.com/spf13/viper"
)

func InitGrpcServer(
	userServer userv1.UserServiceServer,
	tenantServer tenantv1.TenantServiceServer,
	departmentServer departmentv1.DepartmentServiceServer,
) *grpcx.Server {
	var cfg grpcx.ServerConfig
	if err := viper.UnmarshalKey("grpc.server.eiam", &cfg); err != nil {
		panic(err)
	}

	server := grpcx.NewServer(cfg, grpcx.WithJWTAuth(cfg.AuthToken))

	userv1.RegisterUserServiceServer(server, userServer)
	tenantv1.RegisterTenantServiceServer(server, tenantServer)
	departmentv1.RegisterDepartmentServiceServer(server, departmentServer)
	return server
}
