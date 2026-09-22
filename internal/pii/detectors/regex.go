package detectors

import (
	"embed"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"pdn-shield/internal/pii"
)

//go:embed rules.yaml
var rulesFS embed.FS

// ReclassifyRule reclassifies a matched span to another category when a context
// keyword appears within a window to the left or right of the match.
type ReclassifyRule struct {
	Context            []string     `yaml:"context"`
	ContextAfter       []string     `yaml:"context_after"`
	ContextWindow      int          `yaml:"context_window"`
	ContextAfterWindow int          `yaml:"context_after_window"`
	Category           pii.Category `yaml:"category"`
}

// Rule is a single regex-based detection rule.
type Rule struct {
	Name               string           `yaml:"name"`
	Category           pii.Category     `yaml:"category"`
	Pattern            string           `yaml:"pattern"`
	Validator          string           `yaml:"validator"`
	Confidence         float64          `yaml:"confidence"`
	Context            []string         `yaml:"context"`
	RequireContext     bool             `yaml:"require_context"`
	ContextWindow      int              `yaml:"context_window"`
	ContextAfter       []string         `yaml:"context_after"`
	ContextAfterWindow int              `yaml:"context_after_window"`
	Group              int              `yaml:"group"`
	Reclassify         []ReclassifyRule `yaml:"reclassify"`
	// Standalone, when true (default), requires that the character immediately
	// before and after the match is not a digit. This prevents a rule from
	// matching a fragment inside a longer run of digits (e.g. a phone number
	// inside a 20-digit account number).
	Standalone *bool `yaml:"standalone"`
	// NotInDigitSequence, when true, rejects a match that is part of a sequence
	// of digit groups separated by a single space or dash (e.g. card groups).
	NotInDigitSequence bool `yaml:"not_in_digit_sequence"`
	// MatchLower, when true, matches the pattern against the lowercased text
	// (when byte lengths match) so the pattern needs no (?i) for Cyrillic
	// keywords. Only safe for rules whose pattern is case-insensitive.
	MatchLower bool `yaml:"match_lower"`
	// contextWindow is the number of runes to the left scanned for context.
	contextWindow int
	// contextAfterWindow is the number of runes to the right scanned for context.
	contextAfterWindow int
	// contextLower holds the lowercased context keywords.
	contextLower []string
	// contextAfterLower holds the lowercased context_after keywords.
	contextAfterLower []string
	re                *regexp.Regexp
	// reLower is the pattern compiled without (?i), used to match the
	// lowercased text when MatchLower is set and byte lengths match.
	reLower *regexp.Regexp
}

// standalone reports whether the rule requires digit-free boundaries.
func (r *Rule) standalone() bool {
	return r.Standalone == nil || *r.Standalone
}

type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// LoadRules parses rules from r and compiles their patterns.
func LoadRules(r io.Reader) ([]Rule, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}
	for i := range rf.Rules {
		rule := &rf.Rules[i]
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		rule.re = re
		if rule.MatchLower {
			// Compile a case-insensitive variant for the Raw fallback path used
			// when the lowercased text has a different byte length.
			reLower, err := regexp.Compile("(?i)" + rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %q (match_lower fallback): %w", rule.Name, err)
			}
			rule.reLower = reLower
		}
		rule.contextWindow = rule.ContextWindow
		if rule.contextWindow == 0 {
			rule.contextWindow = 40
		}
		rule.contextAfterWindow = rule.ContextAfterWindow
		if rule.contextAfterWindow == 0 {
			rule.contextAfterWindow = 20
		}
		rule.contextLower = make([]string, len(rule.Context))
		for j, kw := range rule.Context {
			rule.contextLower[j] = strings.ToLower(kw)
		}
		rule.contextAfterLower = make([]string, len(rule.ContextAfter))
		for j, kw := range rule.ContextAfter {
			rule.contextAfterLower[j] = strings.ToLower(kw)
		}
		for j := range rule.Reclassify {
			rc := &rule.Reclassify[j]
			for k, kw := range rc.Context {
				rc.Context[k] = strings.ToLower(kw)
			}
			for k, kw := range rc.ContextAfter {
				rc.ContextAfter[k] = strings.ToLower(kw)
			}
		}
	}
	return rf.Rules, nil
}

// DefaultRules loads the embedded rules.yaml.
func DefaultRules() ([]Rule, error) {
	f, err := rulesFS.Open("rules.yaml")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadRules(f)
}

// regexDetector is a pii.Detector driven by a set of rules.
type regexDetector struct {
	rules []Rule
}

// NewRegexDetector builds a pii.Detector from the given rules.
func NewRegexDetector(rules []Rule) pii.Detector {
	return &regexDetector{rules: rules}
}

func (d *regexDetector) Name() string { return "regex" }

func (d *regexDetector) Categories() []pii.Category {
	seen := make(map[pii.Category]bool)
	var cats []pii.Category
	for _, r := range d.rules {
		if !seen[r.Category] {
			seen[r.Category] = true
			cats = append(cats, r.Category)
		}
		for _, rc := range r.Reclassify {
			if !seen[rc.Category] {
				seen[rc.Category] = true
				cats = append(cats, rc.Category)
			}
		}
	}
	return cats
}

func (d *regexDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *regexDetector) DetectLower(t pii.Text) []pii.Span {
	var spans []pii.Span
	for _, r := range d.rules {
		spans = append(spans, d.detectRule(t, r)...)
	}
	return spans
}

// matchText returns the string and regexp the rule's pattern should be matched
// against. When the rule opts into match_lower and byte lengths match, the
// lowercased text is matched with the (?i)-free regexp so Cyrillic keywords
// need no case-insensitive matching. Otherwise the raw text and the
// case-insensitive regexp are used.
func (r Rule) matchText(t pii.Text) (string, *regexp.Regexp) {
	if r.MatchLower && t.LowerOK() && r.reLower != nil {
		return t.Lower, r.reLower
	}
	return t.Raw, r.re
}

func (d *regexDetector) detectRule(t pii.Text, r Rule) []pii.Span {
	text, re := r.matchText(t)
	var spans []pii.Span
	for _, loc := range re.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if r.Group > 0 {
			sub := re.FindStringSubmatchIndex(text[start:end])
			if sub == nil || len(sub) < 2*(r.Group+1) || sub[2*r.Group] < 0 {
				continue
			}
			start = start + sub[2*r.Group]
			end = start + (sub[2*r.Group+1] - sub[2*r.Group])
		} else if re.NumSubexp() > 0 {
			// No explicit group: span covers from the first non-empty capture
			// group to the last non-empty capture group, so context words stay
			// outside the span.
			sub := re.FindStringSubmatchIndex(text[start:end])
			if sub == nil {
				continue
			}
			first, last := -1, -1
			for g := 1; g <= re.NumSubexp(); g++ {
				if sub[2*g] >= 0 {
					if first < 0 {
						first = sub[2*g]
					}
					last = sub[2*g+1]
				}
			}
			if first < 0 {
				continue
			}
			start = start + first
			end = start + (last - first)
		}
		match := t.Raw[start:end]

		// Trim trailing separators so a span never ends with a space, dash,
		// period or comma (e.g. a card number followed by a space).
		for end > start {
			c := t.Raw[end-1]
			if c == ' ' || c == '-' || c == '.' || c == ',' {
				end--
				continue
			}
			break
		}
		match = t.Raw[start:end]

		if r.Validator != "" {
			if v, ok := Validators[r.Validator]; ok && !v(match) {
				continue
			}
		}

		// Standalone: the match must not be adjacent to another digit.
		if r.standalone() {
			if start > 0 && isDigitByte(t.Raw[start-1]) {
				continue
			}
			if end < len(t.Raw) && isDigitByte(t.Raw[end]) {
				continue
			}
		}

		// NotInDigitSequence: reject a match that is part of a sequence of digit
		// groups separated by a single space or dash.
		if r.NotInDigitSequence {
			if isDigitGroupAdjacent(t.Raw, start, end, true) || isDigitGroupAdjacent(t.Raw, start, end, false) {
				continue
			}
		}

		conf := r.Confidence
		if conf == 0 {
			conf = 0.9
		}

		// Context keywords to the left or right raise confidence. A context is
		// satisfied only when no other digit group sits between the keyword and
		// the match. The nearest satisfying keyword yields a small bonus so that
		// competing categories (e.g. cvv vs pin) resolve to the closer keyword.
		hasCtx, dist, win := contextDistance(t, start, end, r)
		if r.RequireContext && !hasCtx {
			continue
		}
		if hasCtx {
			conf += 0.05
			conf += 0.01 * (1 - float64(dist)/float64(win))
		}

		cat := r.Category
		// Reclassification based on context.
		for _, rc := range r.Reclassify {
			win := rc.ContextWindow
			if win == 0 {
				win = r.contextWindow
			}
			if ok, _ := leftContext(t, start, win, rc.Context); ok {
				cat = rc.Category
				break
			}
			afterWin := rc.ContextAfterWindow
			if afterWin == 0 {
				afterWin = r.contextAfterWindow
			}
			if ok, _ := rightContext(t, end, afterWin, rc.ContextAfter); ok {
				cat = rc.Category
				break
			}
		}

		spans = append(spans, pii.Span{
			Start:      start,
			End:        end,
			Category:   cat,
			Detector:   d.Name(),
			Confidence: conf,
		})
	}
	return spans
}

// contextDistance reports whether a context keyword is satisfied to the left or
// right of the match and returns the distance in runes to the nearest satisfying
// keyword together with the window size used.
func contextDistance(t pii.Text, start, end int, r Rule) (bool, int, int) {
	ok, dist := leftContext(t, start, r.contextWindow, r.contextLower)
	win := r.contextWindow
	if ok {
		return true, dist, win
	}
	ok, dist = rightContext(t, end, r.contextAfterWindow, r.contextAfterLower)
	if ok {
		return true, dist, r.contextAfterWindow
	}
	return false, 0, win
}

// leftContext reports whether any keyword appears in the window of size n runes
// immediately to the left of position pos with no digit group between the
// keyword and pos. It returns the distance in runes from the nearest keyword to
// pos. Keywords must already be lowercased.
func leftContext(t pii.Text, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := runeWindowBefore(t, pos, n)
	best := -1
	for _, kw := range keywords {
		if idx := strings.LastIndex(window, kw); idx >= 0 {
			if e := idx + len(kw); e > best {
				best = e
			}
		}
	}
	if best < 0 {
		return false, 0
	}
	if containsDigit(window[best:]) {
		return false, 0
	}
	return true, utf8.RuneCountInString(window[best:])
}

// rightContext reports whether any keyword appears in the window of size n runes
// immediately to the right of position pos with no digit group between pos and
// the keyword. It returns the distance in runes from pos to the nearest keyword.
// Keywords must already be lowercased.
func rightContext(t pii.Text, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := runeWindowAfter(t, pos, n)
	best := -1
	for _, kw := range keywords {
		if idx := strings.Index(window, kw); idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	if best < 0 {
		return false, 0
	}
	if containsDigit(window[:best]) {
		return false, 0
	}
	return true, utf8.RuneCountInString(window[:best])
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

// containsDigit reports whether s contains any ASCII digit.
func containsDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigitByte(s[i]) {
			return true
		}
	}
	return false
}

// isDigitByte reports whether b is an ASCII digit.
func isDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

// isDigitGroupAdjacent reports whether the token immediately before (left=true)
// or after (left=false) the match, separated by a single space or dash, is a
// pure digit group. This detects a match that is part of a sequence of digit
// groups (e.g. card groups) while ignoring keywords that merely end in a digit
// (e.g. "CVV2").
func isDigitGroupAdjacent(text string, start, end int, left bool) bool {
	if left {
		if start < 2 || (text[start-1] != ' ' && text[start-1] != '-') {
			return false
		}
		tokEnd := start - 1
		tokStart := tokEnd
		for tokStart > 0 && text[tokStart-1] != ' ' && text[tokStart-1] != '-' {
			tokStart--
		}
		if tokStart == tokEnd {
			return false
		}
		return allDigits(text[tokStart:tokEnd])
	}
	if end+1 >= len(text) || (text[end] != ' ' && text[end] != '-') {
		return false
	}
	tokStart := end + 1
	tokEnd := tokStart
	for tokEnd < len(text) && text[tokEnd] != ' ' && text[tokEnd] != '-' {
		tokEnd++
	}
	if tokStart == tokEnd {
		return false
	}
	return allDigits(text[tokStart:tokEnd])
}

// allDigits reports whether every byte in s is an ASCII digit.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigitByte(s[i]) {
			return false
		}
	}
	return true
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
