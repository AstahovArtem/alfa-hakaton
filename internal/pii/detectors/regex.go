package detectors

import (
	"embed"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"pdn-shield/internal/pii"
)

//go:embed rules.yaml
var rulesFS embed.FS

// contextBonusWindow is the fixed reference window used to scale the confidence
// bonus for a satisfied context keyword. Using a single reference (rather than
// each rule's own window) makes the bonus depend only on how close the keyword
// is to the match, so a nearer keyword always outranks a farther one.
const contextBonusWindow = 60

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
	// RejectContext, when non-empty, suppresses a match when any keyword appears
	// within RejectContextWindow runes to the left or right. Used to exclude
	// values that are not personal data (e.g. a PIN for a door intercom).
	RejectContext       []string `yaml:"reject_context"`
	RejectContextWindow int      `yaml:"reject_context_window"`
	// DenyContext, when non-empty, suppresses a match when any keyword appears
	// as a substring within DenyContextWindow runes to the left or right. Unlike
	// RejectContext it uses substring matching so inflected forms and stems are
	// caught (e.g. "домофона" for "домофон", "сигнализации" for "сигнализац").
	DenyContext       []string `yaml:"deny_context"`
	DenyContextWindow int      `yaml:"deny_context_window"`
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
	// rejectContextLower holds the lowercased reject_context keywords.
	rejectContextLower []string
	// rejectContextWindow is the number of runes scanned for reject keywords.
	rejectContextWindow int
	// denyContextLower holds the lowercased deny_context keywords.
	denyContextLower []string
	// denyContextWindow is the number of runes scanned for deny keywords.
	denyContextWindow int
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
		if err := compileRule(&rf.Rules[i]); err != nil {
			return nil, err
		}
	}
	return rf.Rules, nil
}

// compileRule compiles a rule's pattern and precomputes its context windows and
// lowercased keywords.
func compileRule(rule *Rule) error {
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("rule %q: %w", rule.Name, err)
	}
	rule.re = re
	if rule.MatchLower {
		// Compile a case-insensitive variant for the Raw fallback path used
		// when the lowercased text has a different byte length.
		reLower, err := regexp.Compile("(?i)" + rule.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q (match_lower fallback): %w", rule.Name, err)
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
	rule.contextLower = lowerAll(rule.Context)
	rule.contextAfterLower = lowerAll(rule.ContextAfter)
	rule.rejectContextLower = lowerAll(rule.RejectContext)
	rule.rejectContextWindow = rule.RejectContextWindow
	if rule.rejectContextWindow == 0 {
		rule.rejectContextWindow = 25
	}
	rule.denyContextLower = lowerAll(rule.DenyContext)
	rule.denyContextWindow = rule.DenyContextWindow
	if rule.denyContextWindow == 0 {
		rule.denyContextWindow = 25
	}
	for j := range rule.Reclassify {
		rc := &rule.Reclassify[j]
		rc.Context = lowerAll(rc.Context)
		rc.ContextAfter = lowerAll(rc.ContextAfter)
	}
	return nil
}

// lowerAll returns the lowercased forms of keywords.
func lowerAll(keywords []string) []string {
	out := make([]string, len(keywords))
	for i, kw := range keywords {
		out[i] = strings.ToLower(kw)
	}
	return out
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
		start, end := spanBounds(text, re, r, loc)
		if start < 0 {
			continue
		}
		end = trimTrailingSeparators(t.Raw, start, end)
		match := t.Raw[start:end]

		if !r.acceptsMatch(t, start, end, match) {
			continue
		}

		conf, ok := r.matchConfidence(t, start, end)
		if !ok {
			continue
		}

		cat := reclassify(t, start, end, r)

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

// matchConfidence computes the confidence for a match, applying the context
// bonus and the require-context gate. It returns false when the match must be
// skipped.
func (r Rule) matchConfidence(t pii.Text, start, end int) (float64, bool) {
	conf := r.Confidence
	if conf == 0 {
		conf = 0.9
	}

	// Context keywords to the left or right raise confidence. A context is
	// satisfied only when no other digit group sits between the keyword and
	// the match. The nearest satisfying keyword yields a small bonus so that
	// competing categories (e.g. cvv vs pin) resolve to the closer keyword.
	hasCtx, dist, _ := contextDistance(t, start, end, r)
	if r.RequireContext && !hasCtx {
		return 0, false
	}
	if hasCtx {
		conf = confidenceWithContext(conf, dist)
	}
	return conf, true
}

// trimTrailingSeparators trims trailing spaces, dashes, periods and commas so a
// span never ends with a separator (e.g. a card number followed by a space).
func trimTrailingSeparators(raw string, start, end int) int {
	for end > start {
		c := raw[end-1]
		if c == ' ' || c == '-' || c == '.' || c == ',' {
			end--
			continue
		}
		break
	}
	return end
}

// confidenceWithContext raises conf for a satisfied context keyword. The bonus
// grows as the keyword gets closer to the match, measured against a fixed
// reference window so that a closer keyword always outranks a farther one
// regardless of a rule's own window size. This lets a nearer "пин-код" beat a
// farther "код безопасности" when both rules match the same number.
func confidenceWithContext(conf float64, dist int) float64 {
	conf += 0.05
	conf += 0.01 * (1 - float64(dist)/float64(contextBonusWindow))
	return conf
}

// spanBounds computes the byte span of a match, honouring the rule's capture
// group. It returns start < 0 when the match has no usable capture.
func spanBounds(text string, re *regexp.Regexp, r Rule, loc []int) (int, int) {
	start, end := loc[0], loc[1]
	if r.Group > 0 {
		return groupBounds(text, re, r.Group, start, end)
	}
	if re.NumSubexp() > 0 {
		return captureBounds(text, re, start, end)
	}
	return start, end
}

// groupBounds narrows the span to the rule's explicit capture group.
func groupBounds(text string, re *regexp.Regexp, group, start, end int) (int, int) {
	sub := re.FindStringSubmatchIndex(text[start:end])
	if sub == nil || len(sub) < 2*(group+1) || sub[2*group] < 0 {
		return -1, 0
	}
	start = start + sub[2*group]
	end = start + (sub[2*group+1] - sub[2*group])
	return start, end
}

// captureBounds spans from the first non-empty capture group to the last
// non-empty capture group, so context words stay outside the span.
func captureBounds(text string, re *regexp.Regexp, start, end int) (int, int) {
	sub := re.FindStringSubmatchIndex(text[start:end])
	if sub == nil {
		return -1, 0
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
		return -1, 0
	}
	start = start + first
	end = start + (last - first)
	return start, end
}

// acceptsMatch reports whether a match passes the validator, standalone and
// digit-sequence checks.
func (r Rule) acceptsMatch(t pii.Text, start, end int, match string) bool {
	if r.Validator != "" {
		if v, ok := Validators[r.Validator]; ok && !v(match) {
			return false
		}
	}
	if r.standalone() && !standaloneBoundary(t.Raw, start, end) {
		return false
	}
	if r.NotInDigitSequence && inDigitSequence(t.Raw, start, end) {
		return false
	}
	if r.rejectedByContext(t, start, end) {
		return false
	}
	return true
}

// standaloneBoundary reports whether the match is not adjacent to another digit.
func standaloneBoundary(raw string, start, end int) bool {
	if start > 0 && isDigitByte(raw[start-1]) {
		return false
	}
	if end < len(raw) && isDigitByte(raw[end]) {
		return false
	}
	return true
}

// inDigitSequence reports whether the match is part of a sequence of digit
// groups separated by a single space or dash.
func inDigitSequence(raw string, start, end int) bool {
	return isDigitGroupAdjacent(raw, start, end, true) || isDigitGroupAdjacent(raw, start, end, false)
}

// rejectedByContext reports whether a reject or deny keyword appears within the
// configured windows to the left or right of the match.
func (r Rule) rejectedByContext(t pii.Text, start, end int) bool {
	// Reject context: if any reject keyword appears within the window to the
	// left or right, the match is not personal data.
	if len(r.rejectContextLower) > 0 {
		if ok, _ := leftContext(t, start, r.rejectContextWindow, r.rejectContextLower); ok {
			return true
		}
		if ok, _ := rightContext(t, end, r.rejectContextWindow, r.rejectContextLower); ok {
			return true
		}
	}
	// Deny context: if any deny keyword appears as a substring within the
	// window to the left or right, the match is not personal data (e.g. a
	// PIN for a door intercom). Substring matching catches inflected forms
	// such as "домофона" and stems such as "сигнализац".
	if len(r.denyContextLower) > 0 {
		if denyContextLeft(t, start, r.denyContextWindow, r.denyContextLower) {
			return true
		}
		if denyContextRight(t, end, r.denyContextWindow, r.denyContextLower) {
			return true
		}
	}
	return false
}

// reclassify returns the category of a match, applying context-based
// reclassification rules.
func reclassify(t pii.Text, start, end int, r Rule) pii.Category {
	cat := r.Category
	for _, rc := range r.Reclassify {
		win := rc.ContextWindow
		if win == 0 {
			win = r.contextWindow
		}
		if ok, _ := leftContext(t, start, win, rc.Context); ok {
			return rc.Category
		}
		afterWin := rc.ContextAfterWindow
		if afterWin == 0 {
			afterWin = r.contextAfterWindow
		}
		if ok, _ := rightContext(t, end, afterWin, rc.ContextAfter); ok {
			return rc.Category
		}
	}
	return cat
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
// pos. Keywords must already be lowercased. A keyword only counts when it is at
// a word boundary (not part of a longer word, e.g. "рожден" must not match
// inside "рождения").
func leftContext(t pii.Text, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := runeWindowBefore(t, pos, n)
	best := -1
	for _, kw := range keywords {
		if idx := lastKeywordIndex(window, kw); idx >= 0 {
			if e := idx + len(kw); e > best {
				best = e
			}
		}
	}
	if best < 0 {
		return false, 0
	}
	if containsDate(window[best:]) {
		return false, 0
	}
	return true, utf8.RuneCountInString(window[best:])
}

// rightContext reports whether any keyword appears in the window of size n runes
// immediately to the right of position pos with no digit group between pos and
// the keyword. It returns the distance in runes from pos to the nearest keyword.
// Keywords must already be lowercased. A keyword only counts when it is at a
// word boundary.
func rightContext(t pii.Text, pos, n int, keywords []string) (bool, int) {
	if len(keywords) == 0 {
		return false, 0
	}
	window := runeWindowAfter(t, pos, n)
	best := -1
	for _, kw := range keywords {
		if idx := firstKeywordIndex(window, kw); idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	if best < 0 {
		return false, 0
	}
	if containsDate(window[:best]) {
		return false, 0
	}
	return true, utf8.RuneCountInString(window[:best])
}

// denyContextLeft reports whether any deny keyword appears as a substring in the
// window of size n runes immediately to the left of byte position pos. Keywords
// must already be lowercased. Substring matching catches inflected forms and
// stems, so no word-boundary check is applied.
func denyContextLeft(t pii.Text, pos, n int, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}
	window := runeWindowBefore(t, pos, n)
	for _, kw := range keywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// denyContextRight reports whether any deny keyword appears as a substring in the
// window of size n runes immediately to the right of byte position pos. Keywords
// must already be lowercased.
func denyContextRight(t pii.Text, pos, n int, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}
	window := runeWindowAfter(t, pos, n)
	for _, kw := range keywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// lastKeywordIndex returns the index of the last occurrence of kw in s that is
// at a word boundary, or -1 if none.
func lastKeywordIndex(s, kw string) int {
	searchFrom := len(s)
	for {
		idx := strings.LastIndex(s[:searchFrom], kw)
		if idx < 0 {
			return -1
		}
		if keywordAtBoundary(s, idx, idx+len(kw)) {
			return idx
		}
		searchFrom = idx
	}
}

// firstKeywordIndex returns the index of the first occurrence of kw in s that is
// at a word boundary, or -1 if none.
func firstKeywordIndex(s, kw string) int {
	searchFrom := 0
	for {
		idx := strings.Index(s[searchFrom:], kw)
		if idx < 0 {
			return -1
		}
		idx += searchFrom
		if keywordAtBoundary(s, idx, idx+len(kw)) {
			return idx
		}
		searchFrom = idx + 1
	}
}

// keywordAtBoundary reports whether the substring s[start:end] is not part of a
// longer word: the rune before start and the rune after end are not letters.
func keywordAtBoundary(s string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if unicode.IsLetter(r) {
			return false
		}
	}
	if end < len(s) {
		r, _ := utf8.DecodeRuneInString(s[end:])
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// dateBetweenRe matches a date-like fragment (numeric or word form) used to
// detect whether a context keyword jumps over another date.
var dateBetweenRe = regexp.MustCompile(
	`\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря|янв|фев|мар|апр|май|июн|июл|авг|сен|сент|окт|ноя|дек)\.?\s+\d{2,4}`,
)

// containsDate reports whether s contains a date-like fragment.
func containsDate(s string) bool {
	return dateBetweenRe.MatchString(s)
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
		return digitGroupBefore(text, start)
	}
	return digitGroupAfter(text, end)
}

// digitGroupBefore reports whether the token immediately before the match,
// separated by a single space or dash, is a pure digit group.
func digitGroupBefore(text string, start int) bool {
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

// digitGroupAfter reports whether the token immediately after the match,
// separated by a single space or dash, is a pure digit group.
func digitGroupAfter(text string, end int) bool {
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
