package mask

import (
	"fmt"
	"strings"

	"pdn-shield/internal/pii"
)

// tokenStrategy replaces a value with [CATEGORY_N], where N is the ordinal
// number of the unique value of that category in the document.
type tokenStrategy struct{}

// NewToken builds the token strategy.
func NewToken() Strategy {
	return &tokenStrategy{}
}

func (s *tokenStrategy) Name() string { return "token" }

func (s *tokenStrategy) Mask(value string, cat pii.Category, doc *DocState) string {
	if doc != nil {
		if m := doc.Memo(value); m != "" {
			return m
		}
	}
	n := 0
	if doc != nil {
		n = doc.Next(cat)
	}
	repl := fmt.Sprintf("[%s_%d]", strings.ToUpper(string(cat)), n)
	if doc != nil {
		doc.Remember(value, repl)
	}
	return repl
}
