package role

import (
	"context"
	"errors"
	"testing"

	"github.com/Havens-blog/e-iam/internal/domain"
	rolesvc "github.com/Havens-blog/e-iam/internal/service/role"
)

// 说明：本文件只验证 handler 的「按 keyword 分派」这一行为，
// 不触碰 DB / Casbin / OPA —— 全部走假体，符合「单测严禁直连外部资源」。

// fakeRoleService 只覆写被测的三个方法，其余方法借嵌入接口满足编译。
// 这样接口后续新增方法时本假体无需同步修改。
type fakeRoleService struct {
	rolesvc.IRoleService

	listCalls   int
	searchKw    []string
	countKw     []string
	searchRoles []domain.Role
	searchErr   error
	countErr    error
}

func (f *fakeRoleService) List(_ context.Context, _, _ int64) ([]domain.Role, int64, error) {
	f.listCalls++
	return []domain.Role{{Code: "all-role"}}, 1, nil
}

func (f *fakeRoleService) Search(_ context.Context, keyword string, _, _ int64) ([]domain.Role, error) {
	f.searchKw = append(f.searchKw, keyword)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.searchRoles, nil
}

func (f *fakeRoleService) CountByKeyword(_ context.Context, keyword string) (int64, error) {
	f.countKw = append(f.countKw, keyword)
	if f.countErr != nil {
		return 0, f.countErr
	}
	return int64(len(f.searchRoles)), nil
}

// TestHandler_listByKeyword 表驱动验证分派规则：
//   - keyword 为空 → 走全量 List（行为与修复前一致）
//   - keyword 非空 → 走 Search + CountByKeyword，且 keyword 原样下传
//   - 任一 Service 报错 → 错误上抛，不吞错
func TestHandler_listByKeyword(t *testing.T) {
	errSearch := errors.New("search boom")
	errCount := errors.New("count boom")

	testCases := []struct {
		name string
		req  ListRoleRequest
		fake *fakeRoleService
		// 期望
		wantListCalls int
		wantSearchKw  []string
		wantCountKw   []string
		wantTotal     int64
		wantRolesLen  int
		wantErr       error
	}{
		{
			name:          "空 keyword → 全量 List，不触发 Search/Count",
			req:           ListRoleRequest{Offset: 0, Limit: 20, Keyword: ""},
			fake:          &fakeRoleService{},
			wantListCalls: 1,
			wantTotal:     1,
			wantRolesLen:  1,
		},
		{
			name:          "非空 keyword → Search + CountByKeyword，并下传关键词",
			req:           ListRoleRequest{Offset: 0, Limit: 20, Keyword: "admin"},
			fake:          &fakeRoleService{searchRoles: []domain.Role{{Code: "admin"}, {Code: "admin-reader"}}},
			wantListCalls: 0,
			wantSearchKw:  []string{"admin"},
			wantCountKw:   []string{"admin"},
			wantTotal:     2,
			wantRolesLen:  2,
		},
		{
			name:          "含空格的关键词原样下传（不做隐式 trim，避免与调用方预期不一致）",
			req:           ListRoleRequest{Offset: 10, Limit: 5, Keyword: "ops "},
			fake:          &fakeRoleService{searchRoles: []domain.Role{{Code: "ops"}}},
			wantListCalls: 0,
			wantSearchKw:  []string{"ops "},
			wantCountKw:   []string{"ops "},
			wantTotal:     1,
			wantRolesLen:  1,
		},
		{
			name:          "Search 报错 → 错误上抛（不再返回全量）",
			req:           ListRoleRequest{Keyword: "boom"},
			fake:          &fakeRoleService{searchErr: errSearch},
			wantListCalls: 0,
			wantSearchKw:  []string{"boom"},
			wantCountKw:   []string{"boom"},
			wantErr:       errSearch,
		},
		{
			name:          "CountByKeyword 报错 → 错误上抛，且不进入 Search",
			req:           ListRoleRequest{Keyword: "boom"},
			fake:          &fakeRoleService{countErr: errCount},
			wantListCalls: 0,
			wantCountKw:   []string{"boom"},
			wantErr:       errCount,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{svc: tc.fake}

			roles, total, err := h.listByKeyword(context.Background(), tc.req)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("期望错误 %v，实际 %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("未预期错误: %v", err)
			}
			if tc.fake.listCalls != tc.wantListCalls {
				t.Errorf("List 调用次数: 期望 %d，实际 %d", tc.wantListCalls, tc.fake.listCalls)
			}
			if got := len(tc.fake.searchKw); got != len(tc.wantSearchKw) {
				t.Fatalf("Search 调用次数: 期望 %d，实际 %d", len(tc.wantSearchKw), got)
			}
			for i, kw := range tc.wantSearchKw {
				if tc.fake.searchKw[i] != kw {
					t.Errorf("Search 第 %d 次关键词: 期望 %q，实际 %q", i+1, kw, tc.fake.searchKw[i])
				}
			}
			for i, kw := range tc.wantCountKw {
				if i >= len(tc.fake.countKw) || tc.fake.countKw[i] != kw {
					t.Errorf("CountByKeyword 第 %d 次关键词不符: 期望 %q，实际 %v", i+1, kw, tc.fake.countKw)
				}
			}
			if total != tc.wantTotal {
				t.Errorf("total: 期望 %d，实际 %d", tc.wantTotal, total)
			}
			if len(roles) != tc.wantRolesLen {
				t.Errorf("roles 长度: 期望 %d，实际 %d", tc.wantRolesLen, len(roles))
			}
		})
	}
}
