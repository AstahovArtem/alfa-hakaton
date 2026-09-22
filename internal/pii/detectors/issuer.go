package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

var issuerContextRe = regexp.MustCompile(`(?i)(?:кем выдан|выдавший орган|орган выдачи|орган, выдавший|выдано|выдан|орган)`)

var issuerStartRe = regexp.MustCompile(`(?i)^\s*:?\s*(ГУ МВД|ГУВД|ОУФМС|УФМС|ОМВД|УВД|ОВД|МВД|ОТДЕЛЕНИЕМ|ОТДЕЛЕНИЕ|ОТДЕЛОМ|ОТДЕЛ|УПРАВЛЕНИЕМ|УПРАВЛЕНИЕ|МИГРАЦИОННЫМ|ПАСПОРТНО-ВИЗОВЫМ|ПАСПОРТНЫМ|ТП|ОП|МП)`)

var issuerTermRe = regexp.MustCompile(`(?i)(?:\n|;|\d{1,2}[./-]\d{1,2}[./-]\d{4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}|код подразделения|к/п|дата выдачи|выдан)`)

// Lowercase-only variants matched against the lowercased text to avoid
// case-folding cost.
var issuerContextLowerRe = regexp.MustCompile(`(?:кем выдан|выдавший орган|орган выдачи|орган, выдавший|выдано|выдан|орган)`)

var issuerStartLowerRe = regexp.MustCompile(`^\s*:?\s*(гу мвд|гувд|оуфмс|уфмс|омвд|увд|овд|мвд|отделением|отделение|отделом|отдел|управлением|управление|миграционным|паспортно-визовым|паспортным|тп|оп|мп)`)

var issuerTermLowerRe = regexp.MustCompile(`(?:\n|;|\d{1,2}[./-]\d{1,2}[./-]\d{4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}|код подразделения|к/п|дата выдачи|выдан)`)

// issuerAbbrevs are abbreviations whose trailing period is not a sentence end.
var issuerAbbrevs = map[string]bool{
	"г": true, "ул": true, "д": true, "кв": true, "пр": true, "пер": true,
	"обл": true, "респ": true, "стр": true, "корп": true, "оф": true,
	"пом": true, "комн": true, "пос": true, "дер": true, "ст": true,
	"гор": true, "наб": true, "пл": true, "ш": true, "р-н": true, "пгт": true,
	"т": true, "др": true, "пр-т": true, "пр-д": true, "б-р": true,
}

// issuerContinuations are words that may follow a comma and still belong to the
// issuing authority name (e.g. "по г. Москве, отделом по району Хамовники").
var issuerContinuations = map[string]bool{
	"по": true, "в": true, "и": true, "г": true, "гор": true, "район": true,
	"района": true, "области": true, "отдел": true, "отделом": true,
	"отделение": true, "отделением": true, "тп": true, "№": true,
	"край": true, "края": true, "округ": true, "округа": true,
}

// issuerAlwaysEnd are words that always terminate the issuing authority value.
var issuerAlwaysEnd = map[string]bool{
	"копия": true, "приложена": true, "документ": true, "дата": true, "код": true,
}

type issuerDetector struct{}

// NewIssuerDetector builds the passport_issuer detector.
func NewIssuerDetector() pii.Detector {
	return &issuerDetector{}
}

func (d *issuerDetector) Name() string { return "issuer" }

func (d *issuerDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatPassportIssuer}
}

func (d *issuerDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *issuerDetector) DetectLower(t pii.Text) []pii.Span {
	text := t.Raw
	search := text
	ctxRe, startRe, termRe := issuerContextRe, issuerStartRe, issuerTermRe
	if t.LowerOK() {
		search = t.Lower
		ctxRe, startRe, termRe = issuerContextLowerRe, issuerStartLowerRe, issuerTermLowerRe
	}
	var spans []pii.Span
	for _, loc := range ctxRe.FindAllStringIndex(search, -1) {
		ctxEnd := loc[1]
		startSub := startRe.FindStringSubmatchIndex(search[ctxEnd:])
		if startSub == nil || startSub[2] < 0 {
			continue
		}
		start := ctxEnd + startSub[2]
		end := issuerEnd(search, start, termRe)
		value := search[start:end]
		value = strings.TrimRight(value, " ,.")
		end = start + len(value)
		if value == "" {
			continue
		}
		spans = append(spans, pii.Span{
			Start:      start,
			End:        end,
			Category:   pii.CatPassportIssuer,
			Detector:   d.Name(),
			Confidence: 0.9,
		})
	}
	return spans
}

// issuerEnd returns the byte offset where the issuer value ends, scanning from
// start for the earliest terminator (sentence end, date, keyword, newline) and
// capping the value at 12 words.
func issuerEnd(text string, start int, termRe *regexp.Regexp) int {
	end := len(text)
	for _, tloc := range termRe.FindAllStringIndex(text[start:], -1) {
		pos := start + tloc[0]
		if pos < end {
			end = pos
		}
	}
	// Sentence-ending periods (not abbreviations).
	for i := start; i < len(text); i++ {
		if text[i] != '.' {
			continue
		}
		if isAbbrevPeriod(text, i) {
			continue
		}
		// A period ends the value if followed by whitespace+capital or end.
		if i+1 == len(text) || (text[i+1] == ' ' && i+2 < len(text) && isUpperRune(rune(text[i+2]))) {
			if i < end {
				end = i
			}
		}
	}
	// A comma ends the value when the following word is not a continuation of
	// the issuing authority (e.g. "..., копия страницы приложена к делу").
	for i := start; i < len(text); i++ {
		if text[i] != ',' {
			continue
		}
		next := nextWord(text, i+1)
		if next == "" {
			continue
		}
		lower := strings.ToLower(next)
		if issuerAlwaysEnd[lower] {
			if i < end {
				end = i
			}
			continue
		}
		if !issuerContinuations[lower] {
			if i < end {
				end = i
			}
		}
	}
	// Cap at 12 words.
	words := strings.Fields(text[start:end])
	if len(words) > 12 {
		cut := start
		for k := 0; k < 12; k++ {
			idx := strings.Index(text[cut:], words[k])
			cut += idx + len(words[k])
		}
		if cut < end {
			end = cut
		}
	}
	return end
}

// isAbbrevPeriod reports whether the period at pos is part of an abbreviation.
func isAbbrevPeriod(text string, pos int) bool {
	// Find the token start before the period.
	tokEnd := pos
	tokStart := tokEnd
	for tokStart > 0 && text[tokStart-1] != ' ' && text[tokStart-1] != '\n' {
		tokStart--
	}
	tok := strings.ToLower(text[tokStart:tokEnd])
	return issuerAbbrevs[tok]
}

// nextWord returns the first whitespace-delimited word at or after pos, or "".
func nextWord(text string, pos int) string {
	for pos < len(text) && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n') {
		pos++
	}
	start := pos
	for pos < len(text) && text[pos] != ' ' && text[pos] != '\t' && text[pos] != '\n' && text[pos] != ',' {
		pos++
	}
	return text[start:pos]
}

func isUpperRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'А' && r <= 'Я') || r == 'Ё'
}
