package role

import (
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/web/user"
	"github.com/Havens-blog/e-iam/internal/web/weberrx"
	"github.com/ecodeclub/ginx"
)

var (
	// 4010503xx: 角色增删改查与继承治理类错误。Transport 层将领域哨兵映射为富语义 Result。
	// 各 handler 调 MapDeleteError / MapInheritanceError / MapUnassignError 一次完成匹配，
	// 消除 `if errors.Is(...) { return ErrX, err }` 样板（此前 Delete/BatchDelete 重复、
	// AddParent/RemoveParent 重复、BatchUnassign/Unassign 重复）。

	// 角色删除场景：系统角色禁止删除 / 角色占用中
	deleteErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrDeleteSystemRole, Result: ErrReservedRoleCode},
		{Sentinel: errs.ErrRoleInUse, Result: ErrRoleInUse},
	}

	// 角色继承场景：自继承 / 循环继承 / 不可变继承
	inheritanceErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrRoleSelfInheritance, Result: ErrRoleSelfInheritance},
		{Sentinel: errs.ErrRoleCycleInheritance, Result: ErrRoleCycleInheritance},
		{Sentinel: errs.ErrImmutableInheritance, Result: ErrImmutableInheritance},
	}

	// 角色移除场景：个人空间 admin 解绑禁止
	unassignErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrPersonalTenantAdminUnassignForbidden, Result: ErrPersonalTenantAdminUnassignForbidden},
	}
)

// MapDeleteError 将角色删除类领域哨兵映射为 Result，未命中回退 ErrRoleDeleteFailed。
func MapDeleteError(err error) ginx.Result {
	return weberrx.Map(err, ErrRoleDeleteFailed, deleteErrorMappings...)
}

// MapInheritanceError 将角色继承类领域哨兵映射为 Result，未命中回退通用失败。
func MapInheritanceError(err error, fallback ginx.Result) ginx.Result {
	return weberrx.Map(err, fallback, inheritanceErrorMappings...)
}

// MapUnassignError 将角色移除类领域哨兵映射为 Result，未命中回退 ErrRoleAssignFailed。
func MapUnassignError(err error) ginx.Result {
	return weberrx.Map(err, ErrRoleAssignFailed, unassignErrorMappings...)
}

var (
	// ErrRoleCreateFailed 创建逻辑错误
	ErrRoleCreateFailed = ginx.Result{Code: 4010501, Msg: "创建角色失败"}
	ErrRoleUpdateFailed = ginx.Result{Code: 4010502, Msg: "更新角色信息失败"}
	ErrRoleListFailed   = ginx.Result{Code: 4010504, Msg: "获取角色列表失败"}
	ErrRoleDeleteFailed = ginx.Result{Code: 4010503, Msg: "注销角色失败"}
	ErrRoleAssignFailed = ginx.Result{Code: 4030904, Msg: "分配角色失败"}
	ErrGetMyRolesFailed = ginx.Result{Code: 4030905, Msg: "获取当前有效角色失败"}

	ErrRoleNotFound = ginx.Result{Code: 4030501, Msg: "该角色标识不存在"}

	ErrInvalidUserId         = ginx.Result{Code: 4010505, Msg: "用户 ID 非法"}
	ErrGetUserFailed         = ginx.Result{Code: 4010506, Msg: "获取用户信息失败"}
	ErrGetUserRoleCodeFailed = ginx.Result{Code: 4010507, Msg: "获取用户角色代码失败"}
	ErrGetRoleDetailFailed   = ginx.Result{Code: 4010508, Msg: "获取角色详情失败"}
	ErrGetRoleAnalysisFailed = ginx.Result{Code: 4010509, Msg: "获取角色权限分析失败"}
	ErrImmutableInheritance  = ginx.Result{Code: 4010510, Msg: "系统级继承关系严禁移除"}
	ErrRoleSelfInheritance   = ginx.Result{Code: 4010511, Msg: "角色禁止继承自身"}
	ErrRoleCycleInheritance  = ginx.Result{Code: 4010512, Msg: "角色继承存在死循环"}

	ErrDeleteSystemRole                     = ginx.Result{Code: 4010513, Msg: "系统预置角色禁止删除"}
	ErrRoleInUse                            = ginx.Result{Code: 4010514, Msg: "角色正在使用中，请先解除所有关联（用户或子角色）后再重试删除"}
	ErrReservedRoleCode                     = ginx.Result{Code: 4010515, Msg: "该标识码为系统保留，禁止手动创建、修改或注销"}
	ErrPersonalTenantAdminUnassignForbidden = ginx.Result{Code: 4010516, Msg: "个人空间无法解绑拥有者的 admin 角色"}

	ErrUnauthenticated = user.ErrUnauthenticated
)
