package mask

import (
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

// fullStrategy replaces every letter and digit in a value with "*", keeping all
// other characters (spaces, dots, hyphens, brackets, "№", commas, "@") in
// place. It fully hides the value while preserving its shape.
type fullStrategy struct{}

// NewFull builds the full strategy.
func NewFull() Strategy {
	return &fullStrategy{}
}

func (s *fullStrategy) Name() string { return "full" }

func (s *fullStrategy) Mask(value string, cat pii.Category, doc *DocState) string {
	if doc != nil {
		if m := doc.Memo(value); m != "" {
			return m
		}
	}
	out := maskFull(value)
	if doc != nil {
		doc.Remember(value, out)
	}
	return out
}

// maskFull replaces every letter and digit with "*", preserving all other
// characters in place.
func maskFull(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if isLetter(r) || (r >= '0' && r <= '9') {
			b.WriteByte('*')
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
