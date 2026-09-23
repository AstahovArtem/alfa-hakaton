package mask

import (
	"fmt"
	"strings"
	"testing"

	"pdn-shield/internal/pii"
)

// TestSyntheticNeverLeaksUnsupportedFormats verifies that every synthetic
// generator falls back to a [CATEGORY_N] token, rather than returning the
// original value unchanged, when the value does not match the format it
// knows how to fake.
func TestSyntheticNeverLeaksUnsupportedFormats(t *testing.T) {
	cases := []struct {
		name  string
		cat   pii.Category
		value string
	}{
		{"foreign phone", pii.CatPhone, "+998 90 123 45 67"},
		{"org inn (10 digits)", pii.CatINN, "7707083893"},
		{"short numeric date", pii.CatDate, "1.2.1990"},
		{"10-digit local phone", pii.CatPhone, "(916) 123-45-67"},
		{"unusual card length", pii.CatCardNumber, "1234 5678"},
		{"unusual snils length", pii.CatSNILS, "123-45"},
		{"unusual passport length", pii.CatPassport, "12345"},
		{"empty name", pii.CatFullName, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSynthetic()
			doc := NewDocState()
			got := s.Mask(tc.value, tc.cat, doc)
			if got == tc.value {
				t.Errorf("Mask(%q, %s) returned the original value unchanged", tc.value, tc.cat)
			}
			if tc.value != "" && strings.Contains(got, tc.value) {
				t.Errorf("Mask(%q, %s) = %q still contains the original value", tc.value, tc.cat, got)
			}
		})
	}
}

// TestNewSeededDistributesSeeds verifies the FNV-to-int64 seed derivation
// does not collapse a large fraction of distinct inputs onto the same seed,
// which used to happen because values with the sign bit set were all clamped
// to math.MaxInt64.
func TestNewSeededDistributesSeeds(t *testing.T) {
	seen := make(map[int64]int)
	const n = 2000
	for i := 0; i < n; i++ {
		value := fmt.Sprintf("+7 (916) 000-00-%02d", i%100) + fmt.Sprintf("-%d", i)
		rng := newSeeded(pii.CatPhone, value)
		seed := rng.Int63()
		seen[seed]++
	}
	// With a healthy spread, no single seed value should dominate. The old
	// bug caused roughly half of all inputs (any hash with the high bit set)
	// to collapse onto exactly one seed, so a large majority would collide.
	maxCount := 0
	for _, c := range seen {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount > n/4 {
		t.Errorf("seed distribution too skewed: most common seed used %d/%d times", maxCount, n)
	}
}

// TestSyntheticDistinctInputsDistinctOutputs is a property test: for many
// detected values of various categories, the synthetic output must never
// equal the original, and distinct inputs must mostly produce distinct
// outputs (collisions are only acceptable as rare exceptions, not the rule).
func TestSyntheticDistinctInputsDistinctOutputs(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()

	var values []struct {
		cat pii.Category
		val string
	}
	for i := 0; i < 200; i++ {
		// Each value below is injective in i over [0,200) so the inputs
		// themselves are genuinely distinct (a repeated input must
		// deterministically repeat its output, which is correct behaviour,
		// not a collision).
		values = append(values,
			struct {
				cat pii.Category
				val string
			}{pii.CatPhone, fmt.Sprintf("+7 (9%02d) 123-45-%02d", i/100, i%100)},
			struct {
				cat pii.Category
				val string
			}{pii.CatINN, fmt.Sprintf("50010073%04d", 2200+i)},
			struct {
				cat pii.Category
				val string
			}{pii.CatCardNumber, fmt.Sprintf("4111 1111 1111 %04d", 1000+i)},
		)
	}

	outputs := make(map[string]int)
	for _, v := range values {
		out := s.Mask(v.val, v.cat, doc)
		if out == v.val {
			t.Fatalf("synthetic output equals original for %s %q", v.cat, v.val)
		}
		outputs[out]++
	}
	collisions := 0
	for _, c := range outputs {
		if c > 1 {
			collisions++
		}
	}
	// A handful of collisions can happen (different categories/values hashing
	// to the same seed by chance, or INN/card control-sum adjustments), but
	// most outputs must be distinct.
	if collisions > len(values)/10 {
		t.Errorf("too many synthetic output collisions: %d/%d distinct inputs collided", collisions, len(values))
	}
}
