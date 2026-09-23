package mask

import (
	"testing"

	"pdn-shield/internal/pii"
)

// TestFullMaskUnicodeLetters checks that maskFull uses unicode.IsLetter rather
// than the old ASCII+Cyrillic-only ranges, so a non-ASCII, non-Cyrillic
// letter such as "é" is masked instead of being left in the clear.
func TestFullMaskUnicodeLetters(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"accentedEmailLocal", "élise@example.fr", "*****@*******.**"},
		{"accentedName", "François Müller", "******** ******"},
	}
	s := NewFull()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Mask(c.in, pii.CatEmail, nil)
			if got != c.want {
				t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
