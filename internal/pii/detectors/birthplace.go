package detectors

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

// birthContextRe matches the keywords that introduce a birth place. It allows
// an optional pronoun ("я") and preposition ("в") between the keyword and the
// value, and an optional separator (":", "—", "-").
var birthContextRe = regexp.MustCompile(`(?i)(?:место рождения|место рожд\.|родился|родилась|родился в|родилась в|рожден в|рождён в|уроженец|уроженка)`)

var birthContextLowerRe = regexp.MustCompile(`(?:место рождения|место рожд\.|родился|родилась|родился в|родилась в|рожден в|рождён в|уроженец|уроженка)`)

// birthValueRe matches the value after a birth-place context keyword. It
// captures the place, skipping an optional date, pronoun and separators.
var birthValueRe = buildBirthValueRe()

var birthValueLowerRe = buildBirthValueLowerRe()

func buildBirthValueRe() *regexp.Regexp {
	return regexp.MustCompile(`(?i)^\s*:?\s*(?:—\s*)?` + birthValueBody(true))
}

func buildBirthValueLowerRe() *regexp.Regexp {
	return regexp.MustCompile(`^\s*:?\s*(?:—\s*)?` + birthValueBody(false))
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
	// An optional date between the context and the place, including abbreviated
	// month names (e.g. "05 мар 1985 в").
	date := `(?:\d{1,2}[./-]\d{1,2}[./-]\d{4}\s+в\s+|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря|янв|фев|мар|апр|май|июн|июл|авг|сен|окт|ноя|дек)\s+\d{4}\s+(?:года?\s+)?в\s+)?`
	// An optional pronoun and preposition between the context and the place
	// (e.g. "Родилась я в Ташкенте"). These stay outside the captured value.
	lead := `(?:я\s+)?(?:в\s+)?`
	prefix := `(?:г\.|гор\.|город|пос\.|посёлок|поселок|село|дер\.|деревня|станица|пгт|с\.|ст\.|аул|х\.|хутор|п\.|рп|д\.)?`
	word := `[а-яё-]+`
	if upper {
		word = `[А-ЯЁ][а-яё-]+`
	}
	place := `(?:` + word + `|` + cityAlt + `)(?:\s+` + word + `){0,2}`
	region := `(?:область|области|обл\.|край|края|район|района|республика|республики)`
	tail := `(?:,?\s*(?:` + region + `\s+` + word + `(?:\s+` + word + `)?|` + word + `\s+` + region + `|` + region + `))?`
	return date + lead + `(` + prefix + `\s*` + place + tail + `)`
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
		// A birth place never extends into a citizenship clause ("гражданство
		// Республики ..."). Truncate the value at that keyword so the following
		// citizenship span is not swallowed by the overlap resolution.
		if idx := strings.Index(value, "граждан"); idx >= 0 {
			end = start + idx
			value = search[start:end]
		}
		// A birth place never extends past a comma unless a region follows (e.g.
		// "г. Краснодар, Краснодарский край").
		if idx := strings.Index(value, ","); idx >= 0 {
			after := strings.TrimSpace(value[idx+1:])
			if !isRegionTail(after) {
				end = start + idx
				value = search[start:end]
			}
		}
		// The value must start with a settlement prefix, a capitalised word or a
		// city from the dictionary; otherwise no span is created (e.g. "родилась
		// в один день с бабушкой").
		if !d.validStart(t, start, value) {
			continue
		}
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

// validStart reports whether the birth-place value begins with a settlement
// prefix, a capitalised word or a city from the dictionary.
func (d *birthplaceDetector) validStart(t pii.Text, start int, value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	// Settlement prefix.
	if strings.HasPrefix(trimmed, "г.") || strings.HasPrefix(trimmed, "гор.") ||
		strings.HasPrefix(trimmed, "пос.") || strings.HasPrefix(trimmed, "с.") ||
		strings.HasPrefix(trimmed, "ст.") || strings.HasPrefix(trimmed, "дер.") ||
		strings.HasPrefix(trimmed, "д.") || strings.HasPrefix(trimmed, "пгт") ||
		strings.HasPrefix(trimmed, "аул") || strings.HasPrefix(trimmed, "х.") ||
		strings.HasPrefix(trimmed, "хутор") || strings.HasPrefix(trimmed, "п.") ||
		strings.HasPrefix(trimmed, "рп") || strings.HasPrefix(trimmed, "город") ||
		strings.HasPrefix(trimmed, "посёлок") || strings.HasPrefix(trimmed, "поселок") ||
		strings.HasPrefix(trimmed, "село") || strings.HasPrefix(trimmed, "деревня") ||
		strings.HasPrefix(trimmed, "станица") {
		return true
	}
	// Capitalised word (in the raw text).
	raw := t.Raw[start : start+len(value)]
	raw = strings.TrimSpace(raw)
	if raw != "" {
		r, _ := utf8.DecodeRuneInString(raw)
		if isUpperRune(r) {
			return true
		}
	}
	// City from the dictionary.
	lower := strings.ToLower(trimmed)
	for _, c := range loadCities().cities {
		if strings.HasPrefix(lower, c) {
			return true
		}
	}
	return false
}

func wordCount(s string) int {
	return len(strings.Fields(s))
}

// isRegionTail reports whether s looks like a region/republic tail that follows
// a comma in a birth place (e.g. "Краснодарский край", "Республика
// Башкортостан", "Астраханской обл.").
func isRegionTail(s string) bool {
	if s == "" {
		return false
	}
	first := strings.Fields(s)[0]
	lower := strings.ToLower(first)
	if lower == "область" || lower == "области" || lower == "обл." ||
		lower == "край" || lower == "края" || lower == "район" ||
		lower == "района" || lower == "республика" || lower == "республики" {
		return true
	}
	// A capitalised adjective ending in -ский/-ская/-ой/-ая (e.g. "Краснодарский").
	if strings.HasSuffix(lower, "ский") || strings.HasSuffix(lower, "ская") ||
		strings.HasSuffix(lower, "ой") || strings.HasSuffix(lower, "ая") {
		return true
	}
	return false
}
