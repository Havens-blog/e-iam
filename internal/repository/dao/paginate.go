package dao

import "gorm.io/gorm"

// Paginate 返回一个 GORM Scope，统一封装分页查询的 Offset/Limit 计算，
// 消除 18 处 DAO 查询方法中 `Offset(int(offset)).Limit(int(limit))` 的重复样板。
//
// 用法：
//
//	db.Scopes(Paginate(offset, limit)).Order("ctime DESC").Find(&rows)
//
// offset/limit 为领域层 int64，此处收敛为 int（GORM DB 参数类型）。
func Paginate(offset, limit int64) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Offset(int(offset)).Limit(int(limit))
	}
}
