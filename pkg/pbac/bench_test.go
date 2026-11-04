package pbac

import (
	"fmt"
	"testing"
)

// benchmarkConditionSimple 构造一个单 Predicate 的简单授权条件。
func benchmarkConditionSimple() *Condition {
	return &Condition{Predicate: &Predicate{
		Key:      PrincipalUsername,
		Operator: StringEquals,
		Values:   []Operand{Literal("alice")},
	}}
}

// benchmarkConditionComplex 构造一棵 3 层嵌套（Any → All → Predicate × N）的复杂条件，
// 用于度量重复校验移除后对多分支求值的收益。
func benchmarkConditionComplex(n int) *Condition {
	leaves := make([]Condition, 0, n)
	for i := 0; i < n; i++ {
		leaves = append(leaves, Condition{Predicate: &Predicate{
			Key:      PrincipalUsername,
			Operator: StringEquals,
			Values:   []Operand{Literal(fmt.Sprintf("user-%d", i))},
		}})
	}
	return &Condition{Any: []Condition{
		{All: leaves},
		{Predicate: &Predicate{
			Key:      PrincipalUsername,
			Operator: StringEquals,
			Values:   []Operand{Literal("alice")},
		}},
	}}
}

func benchmarkAttributes() map[AttributeKey]any {
	return map[AttributeKey]any{
		PrincipalUsername: "alice",
	}
}

// BenchmarkEvaluateCondition_Simple 度量单 Predicate 求值基线。
func BenchmarkEvaluateCondition_Simple(b *testing.B) {
	cond := benchmarkConditionSimple()
	attrs := benchmarkAttributes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateCondition(cond, attrs)
	}
}

// BenchmarkEvaluateCondition_Complex 度量多分支嵌套求值基线（重复校验的主要受益场景）。
func BenchmarkEvaluateCondition_Complex(b *testing.B) {
	cond := benchmarkConditionComplex(8)
	attrs := benchmarkAttributes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateCondition(cond, attrs)
	}
}

// BenchmarkPartialEvaluateAccessScope_Simple 度量数据范围偏求值基线。
func BenchmarkPartialEvaluateAccessScope_Simple(b *testing.B) {
	scope := &AccessScope{Predicate: &Predicate{
		Key:      "ticket:create_by",
		Operator: StringEquals,
		Values:   []Operand{Ref(PrincipalUsername)},
	}}
	attrs := benchmarkAttributes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PartialEvaluateAccessScope(scope, attrs)
	}
}
