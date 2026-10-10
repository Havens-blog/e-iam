package invitation

import (
	"github.com/Havens-blog/e-iam/internal/errs"
	"github.com/Havens-blog/e-iam/internal/web/weberrx"
	"github.com/ecodeclub/ginx"
)

// 4010700xx / 4030700xx: 邀请治理错误码。Transport 层将领域哨兵映射为富语义 Result，
// 各 handler 调 MapVerifyError / MapAcceptError / MapJoinHandleError 一次完成匹配。

var (
	// 邀请校验/接受场景：不存在或过期 / 次数达上限 / 已是成员
	acceptErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrInvitationNotFound, Result: ErrInvitationNotFound},
		{Sentinel: errs.ErrInvitationFull, Result: ErrInvitationFull},
		{Sentinel: errs.ErrAlreadyMember, Result: ErrAlreadyMember},
	}

	// 入驻申请处理场景：无权处理 / 申请已处理
	joinHandleErrorMappings = []weberrx.Mapping{
		{Sentinel: errs.ErrUnauthorizedHandle, Result: ErrUnauthorized},
		{Sentinel: errs.ErrJoinRequestHandled, Result: ErrJoinRequestHandled},
	}
)

// MapVerifyError 将邀请校验类领域哨兵映射为 Result，未命中回退 ErrInvitationVerifyFailed。
func MapVerifyError(err error) ginx.Result {
	// 校验场景不含 AlreadyMember，取 accept 映射的前两项
	return weberrx.Map(err, ErrInvitationVerifyFailed, acceptErrorMappings[:2]...)
}

// MapAcceptError 将邀请接受类领域哨兵映射为 Result，未命中回退 ErrInvitationAcceptFailed。
func MapAcceptError(err error) ginx.Result {
	return weberrx.Map(err, ErrInvitationAcceptFailed, acceptErrorMappings...)
}

// MapJoinHandleError 将入驻申请处理类领域哨兵映射为 Result，未命中回退 ErrJoinRequestHandleFailed。
func MapJoinHandleError(err error) ginx.Result {
	return weberrx.Map(err, ErrJoinRequestHandleFailed, joinHandleErrorMappings...)
}

var (
	ErrInvitationCreateFailed  = ginx.Result{Code: 4010701, Msg: "创建邀请码失败"}
	ErrInvitationListFailed    = ginx.Result{Code: 4010702, Msg: "获取邀请列表失败"}
	ErrInvitationRevokeFailed  = ginx.Result{Code: 4010703, Msg: "撤回邀请链接失败"}
	ErrInvitationVerifyFailed  = ginx.Result{Code: 4010704, Msg: "校验邀请码失败"}
	ErrInvitationAcceptFailed  = ginx.Result{Code: 4010705, Msg: "接受邀请失败"}
	ErrJoinRequestListFailed   = ginx.Result{Code: 4010706, Msg: "获取审批列表失败"}
	ErrJoinRequestHandleFailed = ginx.Result{Code: 4010707, Msg: "处理入驻申请失败"}

	ErrInvitationNotFound = ginx.Result{Code: 4030701, Msg: "邀请链接不存在或已过期"}
	ErrInvitationFull     = ginx.Result{Code: 4030702, Msg: "邀请码使用次数已达上限"}
	ErrAlreadyMember      = ginx.Result{Code: 4030703, Msg: "您已是该租户成员，无需重复加入"}
	ErrUnauthorized       = ginx.Result{Code: 4030704, Msg: "无权处理该申请"}
	ErrTenantAccessDenied = ginx.Result{Code: 4030706, Msg: "跨租户操作已被拒绝，请切换至目标租户空间"}
	ErrJoinRequestHandled = ginx.Result{Code: 4030705, Msg: "申请已处理，请勿重复操作"}
)
