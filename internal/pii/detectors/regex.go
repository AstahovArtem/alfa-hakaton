package detectors

import (
	"embed"
	"fmt"
	"io"
	"regexp"
	"strings"

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
	// contextWindow is the number of runes to the left scanned for context.
	contextWindow int
	// contextAfterWindow is the number of runes to the right scanned for context.
	contextAfterWindow int
	re                 *regexp.Regexp
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
		rule.contextWindow = rule.ContextWindow
		if rule.contextWindow == 0 {
			rule.contextWindow = 40
		}
		rule.contextAfterWindow = rule.ContextAfterWindow
		if rule.contextAfterWindow == 0 {
			rule.contextAfterWindow = 20
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
	var spans []pii.Span
	for _, r := range d.rules {
		spans = append(spans, d.detectRule(text, r)...)
	}
	return spans
}

func (d *regexDetector) detectRule(text string, r Rule) []pii.Span {
	var spans []pii.Span
	for _, loc := range r.re.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if r.Group > 0 {
			sub := r.re.FindStringSubmatchIndex(text[start:end])
			if sub == nil || len(sub) < 2*(r.Group+1) || sub[2*r.Group] < 0 {
				continue
			}
			start = start + sub[2*r.Group]
			end = start + (sub[2*r.Group+1] - sub[2*r.Group])
		} else if r.re.NumSubexp() > 0 {
			// No explicit group: span covers from the first non-empty capture
			// group to the last non-empty capture group, so context words stay
			// outside the span.
			sub := r.re.FindStringSubmatchIndex(text[start:end])
			if sub == nil {
				continue
			}
			first, last := -1, -1
			for g := 1; g <= r.re.NumSubexp(); g++ {
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
		match := text[start:end]

		if r.Validator != "" {
			if v, ok := Validators[r.Validator]; ok && !v(match) {
				continue
			}
		}

		// Standalone: the match must not be adjacent to another digit.
		if r.standalone() {
			if start > 0 && isDigitByte(text[start-1]) {
				continue
			}
			if end < len(text) && isDigitByte(text[end]) {
				continue
			}
		}

		// NotInDigitSequence: reject a match that is part of a sequence of digit
		// groups separated by a single space or dash.
		if r.NotInDigitSequence {
			if isDigitGroupAdjacent(text, start, end, true) || isDigitGroupAdjacent(text, start, end, false) {
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
		hasCtx, dist, win := contextDistance(text, start, end, r)
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
			if ok, _ := leftContext(text, start, win, rc.Context); ok {
				cat = rc.Category
				break
			}
			afterWin := rc.ContextAfterWindow
			if afterWin == 0 {
				afterWin = r.contextAfterWindow
			}
			if ok, _ := rightContext(text, end, afterWin, rc.ContextAfter); ok {
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
func contextDistance(text string, start, end int, r Rule) (bool, int, int) {
	ok, dist := leftContext(text, start, r.contextWindow, r.Context)
	win := r.contextWindow
	if ok {
		return true, dist, win
	}
	ok, dist = rightContext(text, end, r.contextAfterWindow, r.ContextAfter)
	if ok {
		return true, dist, r.contextAfterWindow
	}
	return false, 0, win
}

// leftContext reports whether any keyword appears in the window of size n runes
// immediately to the left of position pos with no digit group between the
// keyword and pos. It returns the distance in runes from the nearest keyword to
// pos.
func leftContext(text string, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := lastNRunes(text[:pos], n)
	lower := strings.ToLower(window)
	best := -1
	for _, kw := range keywords {
		kwl := strings.ToLower(kw)
		if idx := strings.LastIndex(lower, kwl); idx >= 0 {
			if e := idx + len(kwl); e > best {
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
	return true, len([]rune(window[best:]))
}

// rightContext reports whether any keyword appears in the window of size n runes
// immediately to the right of position pos with no digit group between pos and
// the keyword. It returns the distance in runes from pos to the nearest keyword.
func rightContext(text string, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := firstNRunes(text[pos:], n)
	lower := strings.ToLower(window)
	best := -1
	for _, kw := range keywords {
		kwl := strings.ToLower(kw)
		if idx := strings.Index(lower, kwl); idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	if best < 0 {
		return false, 0
	}
	if containsDigit(window[:best]) {
		return false, 0
	}
	return true, len([]rune(window[:best]))
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
