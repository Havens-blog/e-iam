package permission

import (
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

var (
	// ErrAuthMenuFailed 业务逻辑执行失败
	ErrAuthMenuFailed  = ginx.Result{Code: 4040901, Msg: "获取授权菜单树失败"}
	ErrUnauthenticated = user.ErrUnauthenticated
)
