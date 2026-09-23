package pii

import (
	"strings"
	"unicode/utf8"
)

// Pipeline runs a set of detectors over a text and resolves the resulting spans.
type Pipeline struct {
	detectors []Detector
}

// NewPipeline creates a pipeline from the given detectors.
func NewPipeline(ds ...Detector) *Pipeline {
	return &Pipeline{detectors: ds}
}

// Run invokes detectors sequentially, collects spans and applies Resolve.
// The text is lowercased once and shared with detectors that implement
// LowerDetector, avoiding repeated strings.ToLower calls.
func (p *Pipeline) Run(text string) Result {
	t := Text{Raw: text, Lower: strings.ToLower(text)}
	var spans []Span
	for _, d := range p.detectors {
		if ld, ok := d.(LowerDetector); ok {
			spans = append(spans, ld.DetectLower(t)...)
		} else {
			spans = append(spans, d.Detect(text)...)
		}
	}
	return Result{Spans: postProcess(Resolve(spans), t)}
}

// nonPassportContexts are document types whose issue date is not a passport
// issue date. When one appears to the left of a date, the date stays generic.
var nonPassportContexts = []string{
	"в/у", "водительск", "вид на жительство", "внж", "доверенность",
	"справка", "действительн", "билет", "полис", "сертификат", "лицензия",
}

// nonPassportWordContexts are non-passport document keywords matched at a word
// boundary (unlike nonPassportContexts, which use substring matching). "ву"
// (водительское удостоверение) is a short token that must not match inside a
// longer word, so it is matched as a standalone word.
var nonPassportWordContexts = []string{"ву"}

// issueContexts are keywords that mark a passport issue date.
var issueContexts = []string{
	"выдан", "выдано", "выдали", "выдал", "выдала", "дата выдачи", "дату выдачи",
	"получал", "получала", "получил", "получила", "получен", "поменял", "поменяла",
	"doc_issue", "issue",
}

// postProcess applies cross-span reclassification rules that depend on the
// resolved span set and the surrounding text.
func postProcess(spans []Span, t Text) []Span {
	for i := range spans {
		reclassifySpan(spans, i, t)
	}
	return spans
}

// reclassifySpan applies the cross-span reclassification rules to one span.
func reclassifySpan(spans []Span, i int, t Text) {
	if spans[i].Category != CatDate && spans[i].Category != CatBirthDate {
		return
	}
	// A date is a passport issue date when an issue keyword is present and
	// no non-passport document context (в/у, внж, ...) appears to the left,
	// and the issue context is nearer than any birth context.
	if isPassportDate(t, spans[i]) {
		spans[i].Category = CatPassportDate
		return
	}
	if spans[i].Category != CatDate {
		return
	}
	// Table rule: a date in a tab-separated row below a "дата рождения"
	// header is a birth date.
	if isTableBirthDate(t, spans[i]) {
		spans[i].Category = CatBirthDate
		return
	}
	// A bare date that immediately follows a passport_issuer span.
	if followsPassportIssuer(spans, i) {
		spans[i].Category = CatPassportDate
	}
}

// followsPassportIssuer reports whether span i immediately follows a
// passport_issuer span.
func followsPassportIssuer(spans []Span, i int) bool {
	for j := range spans {
		if spans[j].Category != CatPassportIssuer {
			continue
		}
		if spans[i].Start >= spans[j].Start && spans[i].Start-spans[j].End <= 3 {
			return true
		}
	}
	return false
}

// BirthContexts are keywords that mark a birth date. Exported so the
// dateWords detector reuses the same birth-date reclassification.
var BirthContexts = []string{
	"родился", "родилась", "родился", "родились", "родил", "рожден", "рождён",
	"дата рождения", "дату рождения", "уроженец", "уроженка", "г.р.", "г. р.", "д.р.", "др",
	"род.", "род", "рожд.", "рожд", "birth", "dob", "born",
}

// isPassportDate reports whether a date span is a passport issue date.
func isPassportDate(t Text, s Span) bool {
	if hasAnyContext(t, s.Start, 160, nonPassportContexts) {
		return false
	}
	if hasWordContext(t, s.Start, 160, nonPassportWordContexts) {
		return false
	}
	issueLeft := hasAnyContext(t, s.Start, 160, issueContexts)
	issueRight := hasAnyContextAfter(t, s.End, 40, []string{"код подразделения", "к/п", "код подр"})
	if !issueLeft && !issueRight {
		return false
	}
	// Nearest context wins: if a birth context is nearer than the passport
	// issue context, keep the birth classification.
	birthDist := nearestContext(t, s.Start, 160, BirthContexts)
	passDist := nearestContext(t, s.Start, 160, issueContexts)
	if birthDist >= 0 && (passDist < 0 || birthDist < passDist) {
		return false
	}
	return true
}

// nearestContext returns the distance in runes to the nearest keyword within n
// runes to the left of pos, or -1 if none is found.
func nearestContext(t Text, pos, n int, keywords []string) int {
	window := windowBefore(t, pos, n)
	best := -1
	for _, kw := range keywords {
		if idx := strings.LastIndex(window, kw); idx >= 0 {
			d := utf8.RuneCountInString(window[idx:])
			if best < 0 || d < best {
				best = d
			}
		}
	}
	return best
}

// isTableBirthDate reports whether a date sits in a tab-separated table row
// below a "дата рождения" header within 200 runes above.
func isTableBirthDate(t Text, s Span) bool {
	// The date's line must contain a tab.
	lineStart := s.Start
	for lineStart > 0 && t.Raw[lineStart-1] != '\n' {
		lineStart--
	}
	lineEnd := s.End
	for lineEnd < len(t.Raw) && t.Raw[lineEnd] != '\n' {
		lineEnd++
	}
	if !strings.Contains(t.Raw[lineStart:lineEnd], "\t") {
		return false
	}
	// A "дата рождения" header must appear within 200 runes above.
	window := windowBefore(t, s.Start, 200)
	return strings.Contains(window, "дата рождения")
}

// hasAnyContext reports whether any keyword appears within n runes to the left
// of byte position pos, at a word boundary.
func hasAnyContext(t Text, pos, n int, keywords []string) bool {
	window := windowBefore(t, pos, n)
	for _, kw := range keywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// hasWordContext reports whether any keyword appears within n runes to the left
// of byte position pos as a standalone word (not part of a longer word).
func hasWordContext(t Text, pos, n int, keywords []string) bool {
	window := windowBefore(t, pos, n)
	for _, kw := range keywords {
		if lastKeywordIndex(window, kw) >= 0 {
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

// keywordAtBoundary reports whether the substring s[start:end] is not part of a
// longer word: the rune before start and the rune after end are not letters.
func keywordAtBoundary(s string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if isLetterRune(r) {
			return false
		}
	}
	if end < len(s) {
		r, _ := utf8.DecodeRuneInString(s[end:])
		if isLetterRune(r) {
			return false
		}
	}
	return true
}

// hasAnyContextAfter reports whether any keyword appears within n runes to the
// right of byte position pos.
func hasAnyContextAfter(t Text, pos, n int, keywords []string) bool {
	window := windowAfter(t, pos, n)
	for _, kw := range keywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// windowBefore returns the last n runes before byte position pos, lowercased.
func windowBefore(t Text, pos, n int) string {
	start := pos
	count := 0
	for start > 0 && count < n {
		_, size := utf8.DecodeLastRuneInString(t.Raw[:start])
		start -= size
		count++
	}
	return strings.ToLower(t.Raw[start:pos])
}

// windowAfter returns the first n runes after byte position pos, lowercased.
func windowAfter(t Text, pos, n int) string {
	end := pos
	count := 0
	for end < len(t.Raw) && count < n {
		_, size := utf8.DecodeRuneInString(t.Raw[end:])
		end += size
		count++
	}
	return strings.ToLower(t.Raw[pos:end])
}

// isLetterRune reports whether r is a Latin or Cyrillic letter.
func isLetterRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
}
