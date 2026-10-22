package domain

// Tenant 租户空间主体
type Tenant struct {
	ID     int64
	Name   string
	Code   string // 租户编码：唯一标识，如 "acme"
	Domain string // 绑定域名
	Status int    // 1-活跃, 2-禁用

	// 三类治理配置（tenant-management 规格 R2/R6/R7）。
	// 零值即"无约束"语义：配额 0 或负数 = 无限制、白名单空 = 全部允许，
	// 存量租户与个人空间无需回填数据即自动获得正确默认行为
	MaxAccounts    int64           // 最大云账号数配额
	MaxUsers       int64           // 最大用户数配额
	MaxUserGroups  int64           // 最大用户组数配额
	FeatureSwitch  map[string]bool // 功能开关表；nil/空 = 未启用任何差异化开关
	AllowedVendors []string        // 云厂商白名单；nil/空 = 不限制云厂商

	Ctime int64
	Utime int64
}

// Membership 租户成员关联：这只是你和租户之间的"入驻契约"。
// 一切关于"你能干啥"的授权，全部移交给 Casbin 或 RoleService 处理。
type Membership struct {
	ID       int64
	TenantID int64
	UserID   int64
	Ctime    int64
}
