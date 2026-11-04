package health

import (
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

// Handler 提供 eiam 的进程存活探针端点，供 WatchAlert 降级探针 A（tech-design §2.3）作为目标。
// 纯进程探活，不附带 Redis/DB 依赖检查（Redis 会话存储健康由 WatchAlert 侧探针 B 覆盖）。
type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

// PublicRoutes 注册无鉴权的 GET /health（不进入 CheckLogin 中间件）。
func (h *Handler) PublicRoutes(server *gin.Engine) {
	server.GET("/health", ginx.W(h.Health))
}

// Health 返回 TECH-api-001 信封 200 {"code":0,"msg":"ok","data":{}}。
func (h *Handler) Health(_ *ginx.Context) (ginx.Result, error) {
	return ginx.Result{Msg: "ok", Data: gin.H{}}, nil
}
