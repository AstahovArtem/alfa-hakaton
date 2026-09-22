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

// issueContexts are keywords that mark a passport issue date.
var issueContexts = []string{
	"выдан", "выдано", "дата выдачи", "дату выдачи", "получал", "получала",
	"получил", "получила",
}

// postProcess applies cross-span reclassification rules that depend on the
// resolved span set and the surrounding text.
func postProcess(spans []Span, t Text) []Span {
	for i := range spans {
		if spans[i].Category != CatDate && spans[i].Category != CatBirthDate {
			continue
		}
		// A date is a passport issue date when an issue keyword is present and
		// no non-passport document context (в/у, внж, ...) appears to the left,
		// and the issue context is nearer than any birth context.
		if isPassportDate(t, spans[i]) {
			spans[i].Category = CatPassportDate
			continue
		}
		if spans[i].Category != CatDate {
			continue
		}
		// Table rule: a date in a tab-separated row below a "дата рождения"
		// header is a birth date.
		if isTableBirthDate(t, spans[i]) {
			spans[i].Category = CatBirthDate
			continue
		}
		// A bare date that immediately follows a passport_issuer span.
		if followsPassportIssuer(spans, i) {
			spans[i].Category = CatPassportDate
		}
	}
	return spans
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

// birthContexts are keywords that mark a birth date.
var birthContexts = []string{
	"родился", "родилась", "родился", "родились", "родил", "рожден", "рождён",
	"дата рождения", "дату рождения", "уроженец", "уроженка", "г.р.", "г. р.", "д.р.", "др",
}

// isPassportDate reports whether a date span is a passport issue date.
func isPassportDate(t Text, s Span) bool {
	if hasAnyContext(t, s.Start, 160, nonPassportContexts) {
		return false
	}
	issueLeft := hasAnyContext(t, s.Start, 160, issueContexts)
	issueRight := hasAnyContextAfter(t, s.End, 40, []string{"код подразделения", "к/п", "код подр"})
	if !issueLeft && !issueRight {
		return false
	}
	// Nearest context wins: if a birth context is nearer than the passport
	// issue context, keep the birth classification.
	birthDist := nearestContext(t, s.Start, 160, birthContexts)
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
