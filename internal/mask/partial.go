package mask

import (
	"embed"
	"strings"
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
		head, tail := 0, 0
		if r.KeepHead != nil {
			head = *r.KeepHead
		}
		if r.KeepTail != nil {
			tail = *r.KeepTail
		}
		out = maskDigits(value, head, tail, r.Char)
	}
	if doc != nil {
		doc.Remember(value, out)
	}
	return out
}

// maskDigits replaces digits with char except the first keepHead and last
// keepTail digits; all non-digit characters are preserved in place. If there
// are at most head+tail+1 digits, all digits are masked.
func maskDigits(value string, keepHead, keepTail int, char string) string {
	var digitIdx []int
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			digitIdx = append(digitIdx, i)
		}
	}
	if len(digitIdx) == 0 {
		return value
	}
	// Mask all digits if there are too few to keep head+tail.
	if len(digitIdx) <= keepHead+keepTail+1 {
		keepHead, keepTail = 0, 0
	}
	keep := make(map[int]bool)
	for i := 0; i < keepHead && i < len(digitIdx); i++ {
		keep[digitIdx[i]] = true
	}
	for i := 0; i < keepTail && i < len(digitIdx); i++ {
		keep[digitIdx[len(digitIdx)-1-i]] = true
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' && !keep[i] {
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
		// Collect a word (letters, optional inner hyphen).
		start := i
		for i < n {
			r, size = utf8.DecodeRuneInString(value[i:])
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
		// Split hyphenated words into parts.
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
	return b.String()
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
		if r >= '0' && r <= '9' {
			b.WriteString(char)
			i += size
			continue
		}
		if isLetter(r) {
			start := i
			for i < n {
				r, size = utf8.DecodeRuneInString(value[i:])
				if !isLetter(r) {
					break
				}
				i += size
			}
			word := value[start:i]
			first, _ := utf8.DecodeRuneInString(word)
			b.WriteString(string(first))
			b.WriteString(strings.Repeat(char, utf8.RuneCountInString(word)-1))
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
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

// serviceWords are abbreviations kept intact in words mode so the structure of
// an address or issuing authority stays readable.
var serviceWords = map[string]bool{
	"ул": true, "д": true, "кв": true, "г": true, "гор": true, "обл": true,
	"корп": true, "стр": true, "пр-т": true, "пер": true, "овд": true,
	"уфмс": true, "мвд": true, "гу": true, "россии": true, "рф": true,
	"республика": true, "область": true, "край": true, "район": true,
	"отделом": true, "отделением": true, "управлением": true,
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
		if r >= '0' && r <= '9' {
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
		for i < n {
			r, size = utf8.DecodeRuneInString(value[i:])
			if !isLetter(r) {
				break
			}
			i += size
		}
		word := value[start:i]
		lower := strings.ToLower(word)
		if serviceWords[lower] {
			b.WriteString(word)
			continue
		}
		rc := utf8.RuneCountInString(word)
		if rc <= 1 {
			b.WriteString(word)
			continue
		}
		first, _ := utf8.DecodeRuneInString(word)
		b.WriteString(string(first))
		b.WriteString(strings.Repeat(char, rc-1))
	}
	return b.String()
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
}
