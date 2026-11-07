package ioc

import (
	"net"
	"net/http"

	auditevt "github.com/Havens-blog/e-iam/internal/event/audit"
	"github.com/Havens-blog/e-iam/internal/pkg/middleware"
	oidcsvc "github.com/Havens-blog/e-iam/internal/service/idp/oidc"
	"github.com/Havens-blog/e-iam/internal/service/permission"
	audithdl "github.com/Havens-blog/e-iam/internal/web/audit"
	"github.com/Havens-blog/e-iam/internal/web/department"
	"github.com/Havens-blog/e-iam/internal/web/discovery"
	"github.com/Havens-blog/e-iam/internal/web/group"
	healthhdl "github.com/Havens-blog/e-iam/internal/web/health"
	idhdl "github.com/Havens-blog/e-iam/internal/web/identity_source"
	idphdl "github.com/Havens-blog/e-iam/internal/web/idp"
	invitationhdl "github.com/Havens-blog/e-iam/internal/web/invitation"
	permissionhdl "github.com/Havens-blog/e-iam/internal/web/permission"
	"github.com/Havens-blog/e-iam/internal/web/policy"
	rolehdl "github.com/Havens-blog/e-iam/internal/web/role"
	tenanthdl "github.com/Havens-blog/e-iam/internal/web/tenant"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/pkg/ctxutil"
	pkgmiddleware "github.com/Havens-blog/e-iam/pkg/web/middleware"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/server/egin"
)

func InitGinWebServer(sp session.Provider, listener net.Listener, mdls []gin.HandlerFunc,
	userHdl *user.Handler, policyHdl *policy.Handler,
	tenantHdl *tenanthdl.Handler, permissionHdl *permissionhdl.Handler,
	roleHdl *rolehdl.Handler,
	deptHdl *department.Handler, groupHdl *group.Handler,
	identitySourceHdl *idhdl.Handler, invitationHdl *invitationhdl.Handler,
	discoveryHdl *discovery.Handler, auditHdl *audithdl.Handler, idpHdl *idphdl.Handler, tenancyBuilder *pkgmiddleware.TenancyBuilder,
	permSvc permission.IPermissionService, auditProd auditevt.IAuditProducer, km oidcsvc.IKeyManager) *egin.Component {
	session.SetDefaultProvider(sp)

	server := egin.Load("server.egin").Build(egin.WithListener(listener))
	// 开启 ContextWithFallback：使 ctx.Context.Value() 自动 fallback 到 ctx.Request.Context().Value()
	// 这样 ctxutil.GetTenantID(ctx.Context) 无需 ctx.Set 双通道注入即可正确读取
	server.Engine.ContextWithFallback = true
	server.Use(func(ctx *gin.Context) {
		// 强制 SameSite=Lax：上游 cookie.TokenCarrier 未暴露 SameSite 字段，
		// 借助 gin Context.SetSameSite 在 SetCookie 时统一注入，收敛跨站 CSRF 面。
		ctx.SetSameSite(http.SameSiteLaxMode)
		ctx.Header(TokenCarrierHeader, ConfiguredTokenCarrier().String())
		ctx.Request = ctx.Request.WithContext(
			ctxutil.WithClientInfo(ctx.Request.Context(), ctx.ClientIP(), ctx.Request.UserAgent()),
		)
		ctx.Next()
	})
	server.Use(mdls...)

	// 1. 注册公开路由 (无鉴权，天然隔离不经过 Audit 中间件)
	healthhdl.NewHandler().PublicRoutes(server.Engine)
	userHdl.PublicRoutes(server.Engine)
	policyHdl.PublicRoutes(server.Engine)
	tenantHdl.PublicRoutes(server.Engine)
	permissionHdl.PublicRoutes(server.Engine)
	identitySourceHdl.PublicRoutes(server.Engine)
	invitationHdl.PublicRoutes(server.Engine)
	discoveryHdl.PublicRoutes(server.Engine)
	auditHdl.PublicRoutes(server.Engine)
	idpHdl.PublicRoutes(server.Engine)

	// 1.5 服务间调用路由 (独立 S2S 令牌验签，不经用户会话/OPA 鉴权链)
	s2sGroup := server.Engine.Group("/api/s2s", middleware.S2STokenAuth(km))
	s2sGroup.GET("/tenant/detail/:id", ginx.W(tenantHdl.Detail))
	// 统一审计联邦读侧（F1）：fail-closed 双闸门（配置开关 + 租户白名单），
	// 未配置时整体拒答——开放哪些租户由运维显式决策（见联邦设计文档）。
	s2sGroup.GET("/audit/events", ginx.W(auditHdl.FederationEvents))

	// 2. 登录层：验证是否登录
	server.Use(session.CheckLoginMiddleware())

	// 2.1 租户身份构建
	server.Use(tenancyBuilder.Build())

	// 2.2 统一操作与工作空间确立审计 (支持配置化动态控制审计动作与黑名单)
	server.Use(middleware.Audit(auditProd, InitAuditMatcher(InitAuditConfig())))

	// 3. 基础权限层：仅需登录即可访问的私有接口 (如获取菜单)
	permissionHdl.IdentityRoutes(server.Engine)
	userHdl.IdentityRoutes(server.Engine)
	tenantHdl.IdentityRoutes(server.Engine)
	invitationHdl.IdentityRoutes(server.Engine)

	// 4. API 业务鉴权层：基于 RBAC/OPA 的细粒度权限校验
	server.Use(middleware.CheckPermission(permSvc))

	// 5. 注册业务私有路由 (必须通过 OPA 判定)
	userHdl.PrivateRoutes(server.Engine)
	policyHdl.PrivateRoutes(server.Engine)
	tenantHdl.PrivateRoutes(server.Engine)
	roleHdl.PrivateRoutes(server.Engine)
	deptHdl.PrivateRoutes(server.Engine)
	groupHdl.PrivateRoutes(server.Engine)
	permissionHdl.PrivateRoutes(server.Engine)
	identitySourceHdl.PrivateRoutes(server.Engine)
	invitationHdl.PrivateRoutes(server.Engine)
	auditHdl.PrivateRoutes(server.Engine)
	idpHdl.PrivateRoutes(server.Engine)

	return server
}

func InitGinMiddlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		pkgmiddleware.NewCorsBuilder().Build(),
		pkgmiddleware.AccessLogger(),
	}
}
