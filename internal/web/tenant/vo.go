package tenant

import "github.com/Havens-blog/e-iam/internal/domain"

type SwitchTenantReq struct {
	TenantID int64 `json:"tenant_id" binding:"required,gt=0"`
}

type CreateTenantReq struct {
	Name string `json:"name" binding:"required,max=64"`
	Code string `json:"code" binding:"required,max=32"`
	// 三类治理配置均为可选入参：零值即"无约束"语义（配额 0=无限制、
	// 白名单空=全部允许、开关空表），创建时不强制填写
	MaxAccounts    int64           `json:"max_accounts"`
	MaxUsers       int64           `json:"max_users"`
	MaxUserGroups  int64           `json:"max_user_groups"`
	FeatureSwitch  map[string]bool `json:"feature_switch"`
	AllowedVendors []string        `json:"allowed_vendors"`
}

type UpdateTenantReq struct {
	ID     int64  `json:"id" binding:"required"`
	Name   string `json:"name" binding:"required,max=64"`
	Code   string `json:"code" binding:"required,max=32"`
	Domain string `json:"domain"`
	Status int    `json:"status"`
	// 三类治理配置可选更新；nil 字段经整体覆盖式更新落库后等价于"清空配置"
	MaxAccounts    int64           `json:"max_accounts"`
	MaxUsers       int64           `json:"max_users"`
	MaxUserGroups  int64           `json:"max_user_groups"`
	FeatureSwitch  map[string]bool `json:"feature_switch"`
	AllowedVendors []string        `json:"allowed_vendors"`
}

type ListTenantReq struct {
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListTenantsByIDsReq struct {
	IDs []int64 `json:"ids" binding:"required"`
}

type BatchDeleteTenantReq struct {
	IDs []int64 `json:"ids" binding:"required"`
}

type ListUserTenantsReq struct {
	UserID  int64  `json:"user_id"`
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListTenantRes struct {
	Total   int64      `json:"total"`
	Tenants []TenantVO `json:"tenants"`
}

type ListTenantsByIDsRes struct {
	Tenants []TenantVO `json:"tenants"`
}

type TenantVO struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Domain string `json:"domain"`
	Status int    `json:"status"`
	// 三类治理配置原样出参：nil 序列化为 null，语义与空配置等价
	MaxAccounts    int64           `json:"max_accounts"`
	MaxUsers       int64           `json:"max_users"`
	MaxUserGroups  int64           `json:"max_user_groups"`
	FeatureSwitch  map[string]bool `json:"feature_switch"`
	AllowedVendors []string        `json:"allowed_vendors"`
	Ctime          int64           `json:"ctime"`
}

func ToTenantVOs(tenants []domain.Tenant) []TenantVO {
	res := make([]TenantVO, 0, len(tenants))
	for _, t := range tenants {
		res = append(res, ToTenantVO(t))
	}
	return res
}

func ToTenantVO(t domain.Tenant) TenantVO {
	return TenantVO{
		ID:     t.ID,
		Name:   t.Name,
		Code:   t.Code,
		Domain: t.Domain,
		Status: t.Status,
		// 配置字段随详情/列表出参透出，读取契约不丢字段
		MaxAccounts:    t.MaxAccounts,
		MaxUsers:       t.MaxUsers,
		MaxUserGroups:  t.MaxUserGroups,
		FeatureSwitch:  t.FeatureSwitch,
		AllowedVendors: t.AllowedVendors,
		Ctime:          t.Ctime,
	}
}

type ListMembersReq struct {
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListMembersRes struct {
	Total   int64      `json:"total"`
	Members []MemberVO `json:"members"`
}

type MemberVO struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	Email       string `json:"email"`
	Status      int    `json:"status"`
	JobTitle    string `json:"job_title"`
	LastLoginAt int64  `json:"last_login_at"`
	Ctime       int64  `json:"ctime"`
}

type AssignUserReq struct {
	UserID int64 `json:"user_id" binding:"required"`
}

type BatchAssignTenantsReq struct {
	UserIDs   []int64 `json:"user_ids" binding:"required"`
	TenantIDs []int64 `json:"tenant_ids" binding:"required"`
}

type BatchUnassignTenantsReq struct {
	UserIDs   []int64 `json:"user_ids" binding:"required"`
	TenantIDs []int64 `json:"tenant_ids" binding:"required"`
}

type RemoveMemberReq struct {
	UserID int64 `json:"user_id" binding:"required"`
}

type BatchRemoveMembersReq struct {
	UserIDs []int64 `json:"user_ids" binding:"required"`
}
