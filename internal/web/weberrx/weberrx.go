// Package weberrx 提供 Transport 层领域哨兵到 ginx.Result 的统一映射原语，
// 消除各 web 包 handler 中重复的 `if errors.Is(err, errs.ErrX) { return ErrX }` 样板。
//
// 设计：各 web 包在 errs.go 中声明本包的 Mapping 表（哨兵→Result），handler
// 调用 Map(err, fallback, mappings...) 一次完成匹配，未命中走 fallback。
// 与既有 user.MapLoginError（switch 硬编码）并存，新代码优先用 Map。
package weberrx

import (
	"errors"

	"github.com/ecodeclub/ginx"
)

// Mapping 一条领域哨兵→HTTP Result 的映射。
type Mapping struct {
	Sentinel error       // 领域哨兵错误（errs.ErrXxx）
	Result   ginx.Result // 命中时返回的 HTTP 响应
}

// Map 按顺序用 errors.Is 将 err 匹配 mappings；命中返回对应 Result，否则返回 fallback。
// 调用方保留原 err 一并返回（ginx handler 约定 return Result, error），本函数仅决定 Result。
func Map(err error, fallback ginx.Result, mappings ...Mapping) ginx.Result {
	if err == nil {
		return ginx.Result{}
	}
	for _, m := range mappings {
		if errors.Is(err, m.Sentinel) {
			return m.Result
		}
	}
	return fallback
}
