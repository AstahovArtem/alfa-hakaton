package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

var birthContextRe = regexp.MustCompile(`(?i)(?:место рождения|место рожд\.|родился в г\.|родилась в|родился в|рожден в|рождён в|родился|родилась|уроженец|уроженка)`)

var birthValueRe = buildBirthValueRe()

func buildBirthValueRe() *regexp.Regexp {
	var cityParts []string
	for _, c := range loadCities() {
		cityParts = append(cityParts, regexp.QuoteMeta(c))
	}
	cityAlt := strings.Join(cityParts, "|")
	date := `(?:\d{1,2}[./-]\d{1,2}[./-]\d{4}\s+в\s+|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}\s+года?\s+в\s+)?`
	prefix := `(?:г\.|гор\.|город|пос\.|село|дер\.|станица|пгт|с\.|ст\.)?`
	place := `(?:[А-ЯЁ][а-яё-]+|` + cityAlt + `)(?:\s+[А-ЯЁ][а-яё-]+){0,2}`
	region := `(?:область|области|край|края|район|района|республика|республики)`
	tail := `(?:,?\s*(?:` + region + `\s+[А-ЯЁ][а-яё-]+|[А-ЯЁ][а-яё-]+\s+` + region + `|` + region + `))?`
	return regexp.MustCompile(`(?i)^\s*:?\s*` + date + `(` + prefix + `\s*` + place + tail + `)`)
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
	var spans []pii.Span
	for _, loc := range birthContextRe.FindAllStringIndex(text, -1) {
		ctxEnd := loc[1]
		sub := birthValueRe.FindStringSubmatchIndex(text[ctxEnd:])
		if sub == nil || sub[2] < 0 {
			continue
		}
		start := ctxEnd + sub[2]
		end := ctxEnd + sub[3]
		value := text[start:end]
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
