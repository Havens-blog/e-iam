package audit

import (
	"fmt"

	"github.com/ecodeclub/ginx"
)

var (
	ErrListAuthLogsFailed      = ginx.Result{Code: 4011201, Msg: "查询认证审计日志失败"}
	ErrListOperationLogsFailed = ginx.Result{Code: 4011202, Msg: "查询操作审计日志失败"}
	ErrListAuditEventsFailed   = ginx.Result{Code: 4011203, Msg: "查询统一审计事件失败"}
)

// errFederation 联邦读侧拒绝原因（HTTP 403 body，向调用方说明 fail-closed 闸门状态）
func errFederation(msg string) error {
	return fmt.Errorf("联邦读侧拒绝: %s", msg)
}

var (
	errFederationTenantRequired   = errFederation("缺少 tenant_id 参数")
	errFederationTenantInvalid    = errFederation("tenant_id 非法")
	errFederationTenantNotAllowed = errFederation("该租户未授权联邦读取")
)
