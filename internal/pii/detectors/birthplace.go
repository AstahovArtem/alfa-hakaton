package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

var birthContextRe = regexp.MustCompile(`(?i)(?:место рождения|место рожд\.|родился в г\.|родилась в|родился в|рожден в|рождён в|родился|родилась|уроженец|уроженка)`)

var birthValueRe = buildBirthValueRe()

// Lowercase-only variants matched against the lowercased text to avoid
// case-folding cost.
var birthContextLowerRe = regexp.MustCompile(`(?:место рождения|место рожд\.|родился в г\.|родилась в|родился в|рожден в|рождён в|родился|родилась|уроженец|уроженка)`)

var birthValueLowerRe = buildBirthValueLowerRe()

func buildBirthValueRe() *regexp.Regexp {
	return regexp.MustCompile(`(?i)^\s*:?\s*` + birthValueBody(true))
}

func buildBirthValueLowerRe() *regexp.Regexp {
	return regexp.MustCompile(`^\s*:?\s*` + birthValueBody(false))
}

// birthValueBody builds the body of the birth-place value regex. When upper is
// true the place names require an uppercase first letter (for the raw text);
// when false they match lowercase (for the lowercased text).
func birthValueBody(upper bool) string {
	var cityParts []string
	for _, c := range loadCities().cities {
		cityParts = append(cityParts, regexp.QuoteMeta(c))
	}
	cityAlt := strings.Join(cityParts, "|")
	date := `(?:\d{1,2}[./-]\d{1,2}[./-]\d{4}\s+в\s+|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}\s+года?\s+в\s+)?`
	prefix := `(?:г\.|гор\.|город|пос\.|село|дер\.|станица|пгт|с\.|ст\.)?`
	word := `[а-яё-]+`
	if upper {
		word = `[А-ЯЁ][а-яё-]+`
	}
	place := `(?:` + word + `|` + cityAlt + `)(?:\s+` + word + `){0,2}`
	region := `(?:область|области|край|края|район|района|республика|республики)`
	tail := `(?:,?\s*(?:` + region + `\s+` + word + `|` + word + `\s+` + region + `|` + region + `))?`
	return date + `(` + prefix + `\s*` + place + tail + `)`
}

type birthplaceDetector struct{}

// NewBirthplaceDetector builds the birth_place detector.
func NewBirthplaceDetector() pii.Detector {
	return &birthplaceDetector{}
}

func (d *birthplaceDetector) Name() string { return "birthplace" }

func (d *birthplaceDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatBirthPlace}
}

func (d *birthplaceDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *birthplaceDetector) DetectLower(t pii.Text) []pii.Span {
	text := t.Raw
	search := text
	ctxRe, valueRe := birthContextRe, birthValueRe
	if t.LowerOK() {
		search = t.Lower
		ctxRe, valueRe = birthContextLowerRe, birthValueLowerRe
	}
	var spans []pii.Span
	for _, loc := range ctxRe.FindAllStringIndex(search, -1) {
		ctxEnd := loc[1]
		sub := valueRe.FindStringSubmatchIndex(search[ctxEnd:])
		if sub == nil || sub[2] < 0 {
			continue
		}
		start := ctxEnd + sub[2]
		end := ctxEnd + sub[3]
		value := search[start:end]
		if wordCount(value) > 6 {
			continue
		}
		spans = append(spans, pii.Span{
			Start:      start,
			End:        end,
			Category:   pii.CatBirthPlace,
			Detector:   d.Name(),
			Confidence: 0.92,
		})
	}
	return spans
}

func wordCount(s string) int {
	return len(strings.Fields(s))
}
