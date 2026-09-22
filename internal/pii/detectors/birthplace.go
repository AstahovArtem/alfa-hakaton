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
var birthContextRe = regexp.MustCompile(
	`(?i)(?:место рождения|место рожд\.|родился\s+в\s+|родилась\s+в\s+|родился|родилась|рожден в|рождён в|уроженец|уроженка|род\.)`,
)

// settlementPrefixGorod is the "г." settlement prefix.
const settlementPrefixGorod = "г."

// settlementPrefixes lists the settlement prefixes that introduce a place name
// (e.g. "г.", "пос.", "село", "деревня"). Longer prefixes come first so that
// the longest match wins.
var settlementPrefixes = []string{
	"посёлоке", "поселке", "посёлка", "посёлок", "поселок", "деревня", "деревне",
	"станица", "станице", "городе", "город", "гор.", settlementPrefixGorod, "пос.",
	"с.", "ст.", "дер.", "д.", "пгт", "аул", "х.", "хутор", "п.", "рп", "село", "селе",
}

var birthContextLowerRe = regexp.MustCompile(
	`(?:место рождения|место рожд\.|родился\s+в\s+|родилась\s+в\s+|родился|родилась|рожден в|рождён в|уроженец|уроженка|род\.)`,
)

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
	// month names (e.g. "05 мар 1985 в") and a trailing "г.", "г" or "года"
	// before the preposition "в". A bare year (e.g. "1985 году") is also
	// skipped.
	dateTail := `(?:г\.|года|году|г)?\s*`
	date := `(?:` + dateWordsRe.String() + `\s+в\s+|\d{1,2}[./-]\d{1,2}[./-]\d{4}\s+` + dateTail + `в\s+|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря|янв|фев|мар|апр|май|июн|июл|авг|сен|окт|ноя|дек)\s+\d{4}\s+` + dateTail + `в\s+|\d{4}\s+` + dateTail + `в\s+)?`
	// An optional pronoun and preposition between the context and the place
	// (e.g. "Родилась я в Ташкенте"). These stay outside the captured value.
	lead := `(?:я\s+)?(?:в\s+)?`
	prefix := `(?:г\.|гор\.|город|городе|пос\.|посёлок|поселок|село|дер\.|деревня|деревне|станица|пгт|с\.|ст\.|аул|х\.|хутор|п\.|рп|д\.)?`
	word := `[а-яё-]+`
	if upper {
		word = `[А-ЯЁ][а-яё-]+`
	}
	place := `(?:` + word + `|` + cityAlt + `)(?:\s+` + word + `){0,2}`
	region := `(?:область|области|обл\.|край|края|район|района|республика|республики|асср)`
	tail := `(?:,?\s*(?:` + region + `\s+` + word + `(?:\s+` + word + `)?|` + word + `\s+` + region + `|` + region + `)){0,2}`
	return date + lead + `(?P<value>` + prefix + `\s*` + place + tail + `)`
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
	valueIdx := valueRe.SubexpIndex("value")
	for _, loc := range ctxRe.FindAllStringIndex(search, -1) {
		// The "род." abbreviation must be a standalone word, not part of a
		// longer word (e.g. "город.").
		if ctxEndIsRodAbbrev(search, loc) {
			continue
		}
		if span, ok := d.matchAtContext(t, search, loc[1], valueRe, valueIdx); ok {
			spans = append(spans, span)
		}
	}
	return spans
}

// ctxEndIsRodAbbrev reports whether a context match is the "род." abbreviation
// that is part of a longer word (e.g. "город.").
func ctxEndIsRodAbbrev(search string, loc []int) bool {
	return loc[1]-loc[0] == len("род.") && loc[0] > 0 && isLetterRune(runeBefore(search, loc[0]))
}

// matchAtContext builds a birth-place span for the value that follows a context
// keyword ending at ctxEnd.
func (d *birthplaceDetector) matchAtContext(t pii.Text, search string, ctxEnd int, valueRe *regexp.Regexp, valueIdx int) (pii.Span, bool) {
	sub := valueRe.FindStringSubmatchIndex(search[ctxEnd:])
	if sub == nil || sub[2*valueIdx] < 0 {
		return pii.Span{}, false
	}
	start := ctxEnd + sub[2*valueIdx]
	end := ctxEnd + sub[2*valueIdx+1]
	end = trimBirthValue(search, start, end)
	value := search[start:end]
	// The value must start with a settlement prefix, a capitalised word or a
	// city from the dictionary; otherwise no span is created (e.g. "родилась
	// в один день с бабушкой").
	if !d.validStart(t, start, value) {
		return pii.Span{}, false
	}
	// A settlement prefix must be followed by an actual place name. When the
	// prefix is followed by end of text, a period, a comma or a lowercase word
	// not in the dictionary, no span is created (e.g. "родилась ... в деревне").
	if !d.hasPlaceAfterPrefix(t, start, value) {
		return pii.Span{}, false
	}
	// Trim a prepositional settlement prefix (e.g. "в городе Тула" keeps only
	// "Тула", "в деревне Малые Вяземы" keeps only "Малые Вяземы"), while the
	// genitive/nominative forms (e.g. "уроженец города Казани", "аул Хучни") stay
	// part of the value.
	for _, p := range []string{"городе ", "деревне ", "посёлке ", "поселке ", "селе ", "станице "} {
		if strings.HasPrefix(value, p) {
			start += len(p)
			value = search[start:end]
			break
		}
	}
	if wordCount(value) > 10 {
		return pii.Span{}, false
	}
	return pii.Span{
		Start:      start,
		End:        end,
		Category:   pii.CatBirthPlace,
		Detector:   d.Name(),
		Confidence: 0.92,
	}, true
}

// trimBirthValue truncates a birth-place value at a citizenship clause or at a
// comma that is not followed by a region tail.
func trimBirthValue(search string, start, end int) int {
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
		}
	}
	return end
}

// hasPlaceAfterPrefix reports whether a settlement prefix in value is followed
// by an actual place name (a capitalised word or a dictionary city). When the
// prefix is followed by end of text, a period, a comma or a lowercase word not
// in the dictionary, no span is created.
func (d *birthplaceDetector) hasPlaceAfterPrefix(t pii.Text, start int, value string) bool {
	prefixLen := settlementPrefixLen(value)
	if prefixLen < 0 {
		return true
	}
	rest := strings.TrimSpace(value[prefixLen:])
	if rest == "" {
		return false
	}
	// A period or comma right after the prefix means no place name follows.
	if strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, ",") {
		return false
	}
	// The place name must be a capitalised word (in the raw text) or a city
	// from the dictionary.
	raw := t.Raw[start+prefixLen : start+len(value)]
	raw = strings.TrimSpace(raw)
	if raw != "" {
		r, _ := utf8.DecodeRuneInString(raw)
		if isUpperRune(r) {
			return true
		}
	}
	lower := strings.ToLower(rest)
	for _, c := range loadCities().cities {
		if strings.HasPrefix(lower, c) {
			return true
		}
	}
	return false
}

// validStart reports whether the birth-place value begins with a settlement
// prefix, a capitalised word or a city from the dictionary.
func (d *birthplaceDetector) validStart(t pii.Text, start int, value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if hasSettlementPrefix(trimmed) {
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

// hasSettlementPrefix reports whether s starts with a settlement prefix such as
// "г.", "пос.", "село" or "деревня". It uses loose matching so that genitive
// forms like "города Казани" are also accepted.
func hasSettlementPrefix(s string) bool {
	for _, p := range settlementPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// settlementPrefixLen returns the length of the settlement prefix at the start
// of s, or -1 when s does not start with a settlement prefix. The prefix must be
// a complete word: it is followed by a space, a period or the end of the string
// (so "город" does not match the genitive "города").
func settlementPrefixLen(s string) int {
	for _, p := range settlementPrefixes {
		if !strings.HasPrefix(s, p) {
			continue
		}
		after := s[len(p):]
		if after == "" || after[0] == ' ' || after[0] == '.' {
			return len(p)
		}
	}
	return -1
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
	lower := strings.ToLower(strings.Fields(s)[0])
	return isRegionKeyword(lower) || isRegionAdjective(lower)
}

// isRegionKeyword reports whether lower is a region/republic keyword such as
// "область", "край" or "республика".
func isRegionKeyword(lower string) bool {
	switch lower {
	case "область", "области", "обл.", wordKrai, "края", wordRaion,
		"района", "республика", "республики":
		return true
	}
	return false
}

// isRegionAdjective reports whether lower is a capitalised adjective ending in
// -ский/-ская/-ой/-ая (e.g. "Краснодарский").
func isRegionAdjective(lower string) bool {
	return strings.HasSuffix(lower, "ский") || strings.HasSuffix(lower, "ская") ||
		strings.HasSuffix(lower, sufOy) || strings.HasSuffix(lower, "ая")
}
