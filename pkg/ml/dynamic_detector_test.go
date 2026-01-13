package ml

import (
	"strings"
	"testing"
)

// =============================================================================
// PERF-002: Levenshtein Memory Optimization Tests
// Tests verify correctness and benchmark the O(min(m,n)) space optimization.
// =============================================================================

// TestLevenshteinDistance_Correctness verifies the algorithm produces correct results.
func TestLevenshteinDistance_Correctness(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{"empty_strings", "", "", 0},
		{"first_empty", "", "hello", 5},
		{"second_empty", "hello", "", 5},
		{"identical", "hello", "hello", 0},
		{"single_substitution", "hello", "hallo", 1},
		{"single_insertion", "hello", "helllo", 1},
		{"single_deletion", "hello", "helo", 1},
		{"multiple_edits", "kitten", "sitting", 3},
		{"reverse", "abc", "cba", 2},
		{"completely_different", "abc", "xyz", 3},
		{"case_sensitive", "Hello", "hello", 1},
		{"longer_strings", "algorithm", "altruistic", 6},
		// Note: Function operates on bytes, not runes. "é" is 2 bytes (C3 A9).
		// So café (5 bytes: c,a,f,C3,A9) vs cafe (4 bytes: c,a,f,e) = 2 edits
		{"unicode_bytes", "café", "cafe", 2},
		{"one_char", "a", "b", 1},
		{"same_char", "a", "a", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := levenshteinDistance(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d",
					tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestLevenshteinDistance_Symmetry verifies distance(a,b) == distance(b,a).
func TestLevenshteinDistance_Symmetry(t *testing.T) {
	pairs := []struct{ a, b string }{
		{"hello", "world"},
		{"kitten", "sitting"},
		{"", "test"},
		{"abc", "xyz"},
		{"algorithm", "logarithm"},
	}

	for _, p := range pairs {
		d1 := levenshteinDistance(p.a, p.b)
		d2 := levenshteinDistance(p.b, p.a)
		if d1 != d2 {
			t.Errorf("Asymmetry: distance(%q, %q)=%d but distance(%q, %q)=%d",
				p.a, p.b, d1, p.b, p.a, d2)
		}
	}
}

// TestLevenshteinDistance_TriangleInequality verifies d(a,c) <= d(a,b) + d(b,c).
func TestLevenshteinDistance_TriangleInequality(t *testing.T) {
	triples := []struct{ a, b, c string }{
		{"hello", "hallo", "hullo"},
		{"abc", "abd", "acd"},
		{"cat", "car", "bat"},
	}

	for _, tr := range triples {
		dAB := levenshteinDistance(tr.a, tr.b)
		dBC := levenshteinDistance(tr.b, tr.c)
		dAC := levenshteinDistance(tr.a, tr.c)

		if dAC > dAB+dBC {
			t.Errorf("Triangle inequality violated: d(%q,%q)=%d > d(%q,%q)=%d + d(%q,%q)=%d",
				tr.a, tr.c, dAC, tr.a, tr.b, dAB, tr.b, tr.c, dBC)
		}
	}
}

// TestLevenshteinDistance_LargeStrings tests with larger strings to ensure no panics.
func TestLevenshteinDistance_LargeStrings(t *testing.T) {
	// Create large strings
	large1 := strings.Repeat("abcdefghij", 100) // 1000 chars
	large2 := strings.Repeat("abcdefghik", 100) // 1000 chars, differs in last char of each repeat

	// Should complete without panic
	dist := levenshteinDistance(large1, large2)

	// Each repeat differs by 1 char (j vs k), so 100 substitutions
	if dist != 100 {
		t.Errorf("Expected distance 100 for large strings, got %d", dist)
	}
}

// BenchmarkLevenshteinSmall benchmarks with small strings (10 chars).
func BenchmarkLevenshteinSmall(b *testing.B) {
	a := "hello"
	c := "world"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(a, c)
	}
}

// BenchmarkLevenshteinMedium benchmarks with medium strings (100 chars).
func BenchmarkLevenshteinMedium(b *testing.B) {
	a := strings.Repeat("abcdefghij", 10) // 100 chars
	c := strings.Repeat("jihgfedcba", 10) // 100 chars, reversed pattern
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(a, c)
	}
}

// BenchmarkLevenshteinLarge benchmarks with large strings (1000 chars).
func BenchmarkLevenshteinLarge(b *testing.B) {
	a := strings.Repeat("abcdefghij", 100) // 1000 chars
	c := strings.Repeat("jihgfedcba", 100) // 1000 chars, reversed pattern
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(a, c)
	}
}

// BenchmarkLevenshteinAsymmetric benchmarks with asymmetric lengths.
// Tests the optimization where we swap to ensure shorter string is 'b'.
func BenchmarkLevenshteinAsymmetric(b *testing.B) {
	short := "hello"                         // 5 chars
	long := strings.Repeat("abcdefghij", 50) // 500 chars
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(short, long)
	}
}

// BenchmarkLevenshteinMemory measures memory allocations.
func BenchmarkLevenshteinMemory(b *testing.B) {
	a := strings.Repeat("abcdefghij", 100) // 1000 chars
	c := strings.Repeat("jihgfedcba", 100) // 1000 chars

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(a, c)
	}
}
