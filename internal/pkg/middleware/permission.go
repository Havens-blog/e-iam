package middleware

import (
	"errors"
	"log"
	"net/http"
	"reflect"

	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/service/permission"
	"github.com/Havens-blog/e-iam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// CheckPermission 内部鉴权中间件
// 用于 EIAM 自身服务的 API 权限校验
func CheckPermission(svc permission.IPermissionService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 1. 获取登录态
		sess, err := session.Get(&gctx.Context{Context: ctx})
		if err != nil || sess == nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		username, ok := sess.Claims().Data["username"]
		if !ok {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// 2. 识别当前请求对应的逻辑元数据
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		info, ok := capability.GetResourceInfo(ptr)
		if !ok {
			// Fail-Closed：私有路由必须通过 h.Define(...) 显式注册能力元数据。
			// 未注册即视为工程遗漏，直接拒绝而非“仅需登录”放行——
			// 历史缺口（如 /menus）均已迁移至 Identity 分组，此处不再存在合法未注册路由
			log.Printf("路由缺失能力注册被阻断: [method=%s, path=%s, user=%s] 请使用 h.Define(...) 注册", ctx.Request.Method, ctx.FullPath(), username)
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403001,
				Msg:  "路由未注册权限元数据，访问被拒绝",
			})
			return
		}

		// 3. 调用权限服务执行判定
		// 执行逻辑：物理资产发现 -> 逻辑权限匹配 -> OPA 策略演算
		ok, err = svc.CheckAPI(ctx.Request.Context(), username, info.Service, ctx.Request.Method, ctx.FullPath())
		if err != nil {
			// 如果是明确的越权拦截错误，返回 403
			if errors.Is(err, errs.ErrForbidden) {
				ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
					Code: 403001,
					Msg:  err.Error(),
				})
				return
			}

			// 其他未知错误，打印日志并返回 500
			log.Printf("鉴权检查异常: [method=%s, path=%s, user=%s] err: %v", ctx.Request.Method, ctx.Request.URL.Path, username, err)
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403001,
				Msg:  "无权执行该操作，请联系管理员授权",
			})
			return
		}

		ctx.Next()
	}
}
