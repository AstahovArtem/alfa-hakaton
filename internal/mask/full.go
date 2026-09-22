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

// fullServiceWords are the words kept intact by the full strategy: the shared
// serviceWords plus short function words ("по", "в", "и") and the "ОУФМС"
// abbreviation. Keys are lowercase.
var fullServiceWords = func() map[string]bool {
	m := make(map[string]bool, len(serviceWords)+4)
	for sw := range serviceWords {
		m[sw] = true
	}
	for _, sw := range []string{"по", "в", "и", "оуфмс"} {
		m[sw] = true
	}
	return m
}()

// NewFull builds the full strategy.
func NewFull() Strategy {
	return &fullStrategy{}
}

func (s *fullStrategy) Name() string { return "full" }

func (s *fullStrategy) Mask(value string, _ pii.Category, doc *DocState) string {
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
// characters in place. The value is tokenized into words (sequences of letters
// and digits, with a hyphen allowed inside a word); everything between words is
// copied verbatim. A word whose lowercase form (without a trailing dot) is a
// service word (see serviceWords) is kept intact, otherwise every letter and
// digit in it is replaced with "*". Abbreviations with a dot ("г.", "ул.",
// "д.", "кв.", "обл.", "корп.", "стр.", "пр-т") are preserved together with
// the dot. When the whole value consists only of service words (e.g. "РФ",
// "России"), every letter is masked so no service word leaks the value.
func maskFull(value string) string {
	if allServiceWords(value) {
		return maskAllLetters(value)
	}
	var b strings.Builder
	b.Grow(len(value))
	i := 0
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if !isWordRune(r) {
			b.WriteRune(r)
			i += size
			continue
		}
		start := i
		i = scanWord(value, i)
		word := value[start:i]
		if isServiceWord(word) {
			b.WriteString(word)
			continue
		}
		writeMaskedWord(&b, word)
	}
	return b.String()
}

// allServiceWords reports whether every word in value is a service word.
func allServiceWords(value string) bool {
	i := 0
	n := len(value)
	found := false
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if !isWordRune(r) {
			i += size
			continue
		}
		start := i
		i = scanWord(value, i)
		if !isServiceWord(value[start:i]) {
			return false
		}
		found = true
	}
	return found
}

// maskAllLetters replaces every letter and digit in value with "*", keeping all
// other characters in place.
func maskAllLetters(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if isWordRune(r) {
			b.WriteByte('*')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// scanWord advances i past a run of word runes, allowing a single inner hyphen.
func scanWord(value string, i int) int {
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if isWordRune(r) {
			i += size
			continue
		}
		if r == '-' && i+size < n {
			nr, _ := utf8.DecodeRuneInString(value[i+size:])
			if isWordRune(nr) {
				i += size
				continue
			}
		}
		break
	}
	return i
}

// isServiceWord reports whether word (optionally with a trailing dot) is a
// service word that should be kept intact.
func isServiceWord(word string) bool {
	lookup := word
	if strings.HasSuffix(word, ".") {
		lookup = word[:len(word)-1]
	}
	return fullServiceWords[strings.ToLower(lookup)]
}

// writeMaskedWord writes word to b with every letter and digit replaced by "*".
func writeMaskedWord(b *strings.Builder, word string) {
	for _, wr := range word {
		if isWordRune(wr) {
			b.WriteByte('*')
		} else {
			b.WriteRune(wr)
		}
	}
}

// isWordRune reports whether r is a letter or digit that can be part of a word.
func isWordRune(r rune) bool {
	return isLetter(r) || (r >= '0' && r <= '9')
}
