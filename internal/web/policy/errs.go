package policy

import (
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/internal/web/weberrx"
	"github.com/ecodeclub/ginx"
)

// 4050xxx: 策略中心错误码。Transport 层将领域哨兵映射为富语义 Result，
// 各 handler 调 MapCreateError / MapDeleteError 一次完成匹配，消除样板。

var (
	// 策略创建：标识码重复
	createErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrDuplicatePolicyCode, Result: ErrDuplicatePolicyCode},
	}

	// 策略删除：系统预置禁止删除 / 策略占用中
	deleteErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrDeleteSystemPolicy, Result: ErrDeleteSystemPolicy},
		{Sentinel: errs.ErrPolicyInUse, Result: ErrPolicyInUse},
	}
)

// MapCreateError 将策略创建类领域哨兵映射为 Result，未命中回退 ErrCreatePolicyFailed。
func MapCreateError(err error) ginx.Result {
	return weberrx.Map(err, ErrCreatePolicyFailed, createErrorMappings...)
}

// MapDeleteError 将策略删除类领域哨兵映射为 Result，未命中回退 ErrDeletePolicyFailed。
func MapDeleteError(err error) ginx.Result {
	return weberrx.Map(err, ErrDeletePolicyFailed, deleteErrorMappings...)
}

// 策略中心错误码规范：4050xxx
// 目前主要透传 User 模块的认证错误

var (
	ErrUnauthorized    = user.ErrUnauthorized
	ErrUnauthenticated = user.ErrUnauthenticated

	ErrInvalidUserId     = ginx.Result{Code: 4050001, Msg: "用户 ID 非法"}
	ErrInvalidRoleCode   = ginx.Result{Code: 4050014, Msg: "角色代码非法"}
	ErrInvalidGroupCode  = ginx.Result{Code: 4050018, Msg: "用户组代码非法"}
	ErrGetUserFailed     = ginx.Result{Code: 4050002, Msg: "获取用户信息失败"}
	ErrGetAttachedFailed = ginx.Result{Code: 4050003, Msg: "获取关联策略失败"}

	ErrInvalidPolicyCode = ginx.Result{Code: 4050004, Msg: "策略标识非法"}
	ErrGetPolicyFailed   = ginx.Result{Code: 4050005, Msg: "获取策略信息失败"}
	ErrGetSummaryFailed  = ginx.Result{Code: 4050006, Msg: "获取摘要分析失败"}

	ErrCreatePolicyFailed      = ginx.Result{Code: 4050007, Msg: "创建策略失败"}
	ErrUpdatePolicyFailed      = ginx.Result{Code: 4050008, Msg: "更新策略失败"}
	ErrListPolicyFailed        = ginx.Result{Code: 4050009, Msg: "查询策略列表失败"}
	ErrAttachPolicyFailed      = ginx.Result{Code: 4050010, Msg: "绑定策略失败"}
	ErrDetachPolicyFailed      = ginx.Result{Code: 4050011, Msg: "解绑策略失败"}
	ErrBatchAttachPolicyFailed = ginx.Result{Code: 4050012, Msg: "批量绑定策略失败"}
	ErrDuplicatePolicyCode     = ginx.Result{Code: 4050013, Msg: "策略标识码已存在(请勿与系统级策略冲突)"}
	ErrDeletePolicyFailed      = ginx.Result{Code: 4050015, Msg: "删除策略失败"}
	ErrPolicyInUse             = ginx.Result{Code: 4050016, Msg: "策略正在使用中，无法删除"}
	ErrDeleteSystemPolicy      = ginx.Result{Code: 4050017, Msg: "系统预置策略禁止删除"}
)
