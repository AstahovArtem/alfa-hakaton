package detectors

import (
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

// isLetterRune reports whether r is a Latin or Cyrillic letter.
func isLetterRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
}

// isUpperRune reports whether r is an uppercase Latin or Cyrillic letter.
func isUpperRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'А' && r <= 'Я') || r == 'Ё'
}

// runeBefore returns the rune that ends at byte position pos in s.
func runeBefore(s string, pos int) rune {
	if pos <= 0 {
		return 0
	}
	i := pos - 1
	for i > 0 && s[i]&0xC0 == 0x80 {
		i--
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r
}

// decodedRune returns the rune at byte position pos in s.
func decodedRune(s string, pos int) rune {
	r, _ := utf8.DecodeRuneInString(s[pos:])
	return r
}

// gapRunes returns the number of runes between byte positions a and b.
func gapRunes(text string, a, b int) int {
	if b <= a {
		return 0
	}
	return utf8.RuneCountInString(text[a:b])
}

// runeWindowBefore returns the last n runes before byte position pos, taken from
// the lowercased text when byte lengths match, otherwise from the raw text. The
// window is lowercased in the fallback path. No []rune allocation is performed.
func runeWindowBefore(t pii.Text, pos, n int) string {
	if t.LowerOK() {
		return lastNRunesLower(t.Lower[:pos], n)
	}
	return strings.ToLower(lastNRunes(t.Raw[:pos], n))
}

// runeWindowAfter returns the first n runes after byte position pos, taken from
// the lowercased text when byte lengths match, otherwise from the raw text. The
// window is lowercased in the fallback path. No []rune allocation is performed.
func runeWindowAfter(t pii.Text, pos, n int) string {
	if t.LowerOK() {
		return firstNRunesLower(t.Lower[pos:], n)
	}
	return strings.ToLower(firstNRunes(t.Raw[pos:], n))
}

// lastNRunesLower returns the last n runes of s as a string without allocating
// a []rune. It walks back from the end over rune boundaries.
func lastNRunesLower(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	// Walk back n runes from the end.
	i := len(s)
	for count := 0; count < n && i > 0; count++ {
		i--
		for i > 0 && s[i]&0xC0 == 0x80 {
			i--
		}
	}
	return s[i:]
}

// firstNRunesLower returns the first n runes of s as a string without allocating
// a []rune. It walks forward over rune boundaries.
func firstNRunesLower(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for count := 0; count < n && i < len(s); count++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

// lastNRunes returns the last n runes of s as a string.
func lastNRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// firstNRunes returns the first n runes of s as a string.
func firstNRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
