package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestApplication_CanRepresentTenant 表驱动覆盖 S2S 租户授权范围语义:
// 空列表 = 禁止;-1 = 全租户通配;非法租户(<=0)一律拒绝(fail-closed)。
func TestApplication_CanRepresentTenant(t *testing.T) {
	testCases := []struct {
		name     string
		allowed  []int64
		tenantID int64
		want     bool
	}{
		{name: "空列表(nil)禁止代表任何租户", allowed: nil, tenantID: 3, want: false},
		{name: "空列表([])禁止代表任何租户", allowed: []int64{}, tenantID: 5, want: false},
		{name: "非法租户0一律拒绝", allowed: []int64{3}, tenantID: 0, want: false},
		{name: "负数租户一律拒绝", allowed: []int64{-1}, tenantID: -2, want: false},
		{name: "具体列表命中", allowed: []int64{3, 5, 7}, tenantID: 3, want: true},
		{name: "具体列表未命中", allowed: []int64{3, 5, 7}, tenantID: 99, want: false},
		{name: "全租户通配命中任意合法租户", allowed: []int64{-1}, tenantID: 3, want: true},
		{name: "全租户通配命中大ID租户", allowed: []int64{-1}, tenantID: 999, want: true},
		{name: "全租户通配仍拒绝非法租户0", allowed: []int64{-1}, tenantID: 0, want: false},
		{name: "混合列表:通配优先", allowed: []int64{-1, 3}, tenantID: 88, want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := Application{AllowedTenants: tc.allowed}
			assert.Equal(t, tc.want, app.CanRepresentTenant(tc.tenantID))
		})
	}
}
