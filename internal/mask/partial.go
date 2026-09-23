package mask

import (
	"embed"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"pdn-shield/internal/pii"
)

//go:embed partial.yaml
var partialFS embed.FS

// partialConfig is the parsed partial.yaml.
type partialConfig struct {
	Defaults   partialRule                  `yaml:"defaults"`
	Categories map[pii.Category]partialRule `yaml:"categories"`
}

// partialRule configures masking for one category.
type partialRule struct {
	Mode     string `yaml:"mode"`
	KeepHead *int   `yaml:"keep_head"`
	KeepTail *int   `yaml:"keep_tail"`
	Char     string `yaml:"char"`
}

// partialStrategy masks values by category using the partial.yaml rules.
type partialStrategy struct {
	defaults partialRule
	cats     map[pii.Category]partialRule
}

// NewPartial builds the default partial strategy from the embedded config.
func NewPartial() (Strategy, error) {
	data, err := partialFS.ReadFile("partial.yaml")
	if err != nil {
		return nil, err
	}
	var cfg partialConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Defaults.Char == "" {
		cfg.Defaults.Char = "*"
	}
	if cfg.Defaults.KeepHead == nil {
		cfg.Defaults.KeepHead = intPtr(2)
	}
	if cfg.Defaults.KeepTail == nil {
		cfg.Defaults.KeepTail = intPtr(2)
	}
	return &partialStrategy{defaults: cfg.Defaults, cats: cfg.Categories}, nil
}

func intPtr(n int) *int { return &n }

// MustPartial builds the default partial strategy, panicking on error.
func MustPartial() Strategy {
	s, err := NewPartial()
	if err != nil {
		panic(err)
	}
	return s
}

func (s *partialStrategy) Name() string { return "partial" }

func (s *partialStrategy) rule(cat pii.Category) partialRule {
	r := s.defaults
	if cr, ok := s.cats[cat]; ok {
		if cr.Mode != "" {
			r.Mode = cr.Mode
		}
		if cr.KeepHead != nil {
			r.KeepHead = cr.KeepHead
		}
		if cr.KeepTail != nil {
			r.KeepTail = cr.KeepTail
		}
		if cr.Char != "" {
			r.Char = cr.Char
		}
	}
	return r
}

func (s *partialStrategy) Mask(value string, cat pii.Category, doc *DocState) string {
	if doc != nil {
		if m := doc.Memo(value); m != "" {
			return m
		}
	}
	r := s.rule(cat)
	var out string
	switch r.Mode {
	case "initials":
		out = maskInitials(value)
	case "date":
		out = maskDate(value, r.Char)
	case "email":
		out = maskEmail(value, r.Char)
	case "words":
		out = maskWords(value, r.Char)
	default:
		out = maskDigitsByRule(value, r)
	}
	if doc != nil {
		doc.Remember(value, out)
	}
	return out
}

// maskDigitsByRule masks the digits of value using the keep-head/keep-tail
// counts from the rule.
func maskDigitsByRule(value string, r partialRule) string {
	head, tail := 0, 0
	if r.KeepHead != nil {
		head = *r.KeepHead
	}
	if r.KeepTail != nil {
		tail = *r.KeepTail
	}
	return maskDigits(value, head, tail, r.Char)
}

// maskDigits replaces digits with char except the first keepHead and last
// keepTail digits; all non-digit characters are preserved in place. If there
// are at most head+tail+1 digits, all digits are masked.
func maskDigits(value string, keepHead, keepTail int, char string) string {
	digitIdx := collectDigitIdx(value)
	if len(digitIdx) == 0 {
		return value
	}
	// Mask all digits if there are too few to keep head+tail.
	if len(digitIdx) <= keepHead+keepTail+1 {
		keepHead, keepTail = 0, 0
	}
	keep := keepSet(digitIdx, keepHead, keepTail)
	return maskDigitRuns(value, keep, char)
}

// collectDigitIdx returns the byte offsets of every digit in value.
func collectDigitIdx(value string) []int {
	var digitIdx []int
	for i := 0; i < len(value); i++ {
		if isDigit(rune(value[i])) {
			digitIdx = append(digitIdx, i)
		}
	}
	return digitIdx
}

// keepSet returns the set of digit offsets to keep unmasked: the first keepHead
// and the last keepTail digits.
func keepSet(digitIdx []int, keepHead, keepTail int) map[int]bool {
	keep := make(map[int]bool)
	for i := 0; i < keepHead && i < len(digitIdx); i++ {
		keep[digitIdx[i]] = true
	}
	for i := 0; i < keepTail && i < len(digitIdx); i++ {
		keep[digitIdx[len(digitIdx)-1-i]] = true
	}
	return keep
}

// maskDigitRuns replaces every digit not in keep with char, preserving all
// other characters in place.
func maskDigitRuns(value string, keep map[int]bool, char string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if isDigit(rune(value[i])) && !keep[i] {
			b.WriteString(char)
		} else {
			b.WriteByte(value[i])
		}
	}
	return b.String()
}

// maskInitials turns each word into its first uppercase letter plus a dot.
// Existing initials like "И." stay as-is; hyphenated surnames become "С.-Щ.".
func maskInitials(value string) string {
	var b strings.Builder
	i := 0
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if !isLetter(r) {
			b.WriteRune(r)
			i += size
			continue
		}
		start := i
		i = scanLetterWord(value, i)
		// A single-letter word followed by a dot is an initial; consume the dot.
		if utf8.RuneCountInString(value[start:i]) == 1 && i < n && value[i] == '.' {
			i++
		}
		word := value[start:i]
		// If the word is already an initial (single letter + dot), keep it.
		if isInitial(word) {
			b.WriteString(word)
			continue
		}
		writeInitialWord(&b, word)
	}
	return b.String()
}

// scanLetterWord advances i past a run of letters, allowing a single inner
// hyphen.
func scanLetterWord(value string, i int) int {
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if isLetter(r) {
			i += size
			continue
		}
		if r == '-' && i+size < n {
			nr, _ := utf8.DecodeRuneInString(value[i+size:])
			if isLetter(nr) {
				i += size
				continue
			}
		}
		break
	}
	return i
}

// writeInitialWord writes word to b as its first uppercase letter plus a dot,
// splitting hyphenated parts (e.g. "С.-Щ.").
func writeInitialWord(b *strings.Builder, word string) {
	parts := strings.Split(word, "-")
	for pi, p := range parts {
		if pi > 0 {
			b.WriteByte('-')
		}
		first, _ := utf8.DecodeRuneInString(p)
		b.WriteString(strings.ToUpper(string(first)))
		b.WriteByte('.')
	}
}

// isInitial reports whether s is a single letter followed by a dot.
func isInitial(s string) bool {
	r := []rune(s)
	return len(r) == 2 && isLetter(r[0]) && r[1] == '.'
}

// maskDate replaces all digits with char and keeps separators; a month word
// becomes its first letter plus char*(len-1).
func maskDate(value string, char string) string {
	var b strings.Builder
	i := 0
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if isDigit(r) {
			b.WriteString(char)
			i += size
			continue
		}
		if isLetter(r) {
			start := i
			i = scanLetters(value, i)
			b.WriteString(maskDateWord(value[start:i], char))
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// maskDateWord masks a month word: first letter plus char*(len-1).
func maskDateWord(word, char string) string {
	first, _ := utf8.DecodeRuneInString(word)
	return string(first) + strings.Repeat(char, utf8.RuneCountInString(word)-1)
}

// maskEmail masks the local part: first letter + char*(len-1), domain kept.
func maskEmail(value string, char string) string {
	at := strings.Index(value, "@")
	if at < 0 {
		return value
	}
	local := value[:at]
	domain := value[at:]
	if local == "" {
		return value
	}
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + strings.Repeat(char, utf8.RuneCountInString(local)-1) + domain
}

// maskWords keeps the first letter of each word longer than one rune and masks
// the rest; service abbreviations are kept whole. Digit runs are fully masked.
// Punctuation is preserved.
func maskWords(value string, char string) string {
	var b strings.Builder
	i := 0
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if isDigit(r) {
			b.WriteString(char)
			i += size
			continue
		}
		if !isLetter(r) {
			b.WriteRune(r)
			i += size
			continue
		}
		start := i
		i = scanLetters(value, i)
		b.WriteString(maskWord(value[start:i], char))
	}
	return b.String()
}

// scanLetters advances i past a run of letters.
func scanLetters(value string, i int) int {
	n := len(value)
	for i < n {
		r, size := utf8.DecodeRuneInString(value[i:])
		if !isLetter(r) {
			break
		}
		i += size
	}
	return i
}

// maskWord masks a single word: keeps the first letter and replaces the rest
// with char. Service abbreviations and single-letter words are kept whole.
func maskWord(word, char string) string {
	if serviceWords[strings.ToLower(word)] {
		return word
	}
	rc := utf8.RuneCountInString(word)
	if rc <= 1 {
		return word
	}
	first, _ := utf8.DecodeRuneInString(word)
	return string(first) + strings.Repeat(char, rc-1)
}

// isDigit reports whether r is a digit. It uses unicode.IsDigit rather than an
// ASCII-only range so digits from other scripts are also recognized
// consistently with isLetter.
func isDigit(r rune) bool {
	return unicode.IsDigit(r)
}

// isLetter reports whether r is a letter. It uses unicode.IsLetter rather than
// custom ASCII+Cyrillic ranges so accented and other non-ASCII, non-Cyrillic
// letters (e.g. "é") are masked instead of being left in the clear.
func isLetter(r rune) bool {
	return unicode.IsLetter(r)
}
