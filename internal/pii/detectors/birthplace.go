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
	`(?i)(?:место рождения|место рожд\.|город рождения|родился\s+в\s+|родилась\s+в\s+|родился|родилась|рожден в|рождён в|уроженец|уроженка|род\.|ур\.|\bborn\b)`,
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
	"кишлаке", "кишлак",
}

// birthStopWords are lowercase words that must not be treated as the start of
// a lowercase place name following a settlement prefix (e.g. relative
// pronouns that cannot begin a place name).
var birthStopWords = map[string]bool{
	"как": true, "где": true, "когда": true, "что": true, "который": true,
	"которая": true, "которое": true, "которые": true,
}

var birthContextLowerRe = regexp.MustCompile(
	`(?:место рождения|место рожд\.|город рождения|родился\s+в\s+|родилась\s+в\s+|родился|родилась|рожден в|рождён в|уроженец|уроженка|род\.|ур\.|\bborn\b)`,
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
	// (e.g. "Родилась я в Ташкенте", "born in Baku"). These stay outside the
	// captured value.
	lead := `(?:я\s+)?(?:в\s+|in\s+)?`
	prefix := `(?:г\.|гор\.|город|городе|пос\.|посёлок|поселок|село|дер\.|деревня|деревне|станица|пгт|с\.|ст\.|аул|х\.|хутор|п\.|рп|д\.|кишлак|кишлаке)?`
	word := `[а-яё-]+`
	// The first word of the place may also be a Latin name (e.g. "Baku") for
	// an English birth statement; a continuation word stays Cyrillic-only so a
	// following English filler word ("on", "and", ...) is never swept in.
	firstWord := `[а-яё-]+|[a-z-]+`
	if upper {
		word = `[А-ЯЁ][а-яё-]+`
		firstWord = `[А-ЯЁ][а-яё-]+|[A-Z][A-Za-z-]+`
	}
	place := `(?:` + firstWord + `|` + cityAlt + `)(?:\s+` + word + `){0,1}`
	// Longer alternatives come first so e.g. "района" wins over its prefix
	// "район" (regexp alternation picks the first alternative that matches).
	region := `(?:область|области|обл\.|край|края|района|район|республики|республика|асср)`
	// regionLeading is the subset of region keywords that can precede the
	// region's proper name (e.g. "Республики Дагестан", "Республика Северная
	// Осетия"). "область"/"край"/"район"/"асср" only ever follow the proper
	// name (e.g. "Челябинской области"), so allowing them to lead into an
	// arbitrary trailing word would swallow unrelated text (e.g. a "область"
	// at the end of a line followed by the next field's first word).
	regionLeading := `(?:республики|республика)`
	bareRegion := `(?:` + strings.Join(bareRegionNames, "|") + `)`
	tail := `(?:,?\s*(?:` + regionLeading + `\s+` + word + `(?:\s+` + word + `)?|` + word + `\s+` + region + `|` + region + `|` + bareRegion + `)){0,2}`
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
		// A "." abbreviation ("род.", "ур.") must be a standalone word, not
		// part of a longer word (e.g. "город.").
		if ctxEndIsAbbrevInWord(search, loc) {
			continue
		}
		// A famous person's birth place is not personal data: when the subject
		// before "родился/родилась" is a famous name (with no client marker and
		// no other PII in the line), no birth_place span is created.
		if isBornContext(search, loc) && famousSubjectBefore(t, loc[0]) {
			continue
		}
		if span, ok := d.matchAtContext(t, search, loc[1], valueRe, valueIdx); ok {
			spans = append(spans, span)
		}
	}
	return spans
}

// isBornContext reports whether the context match at loc is a "родился" or
// "родилась" keyword (as opposed to "место рождения", "уроженец", etc.). The
// "родил" prefix covers "родился", "родилась" and "родились".
func isBornContext(search string, loc []int) bool {
	ctx := search[loc[0]:loc[1]]
	return strings.HasPrefix(ctx, "родил")
}

// ctxEndIsAbbrevInWord reports whether a context match ending in a period
// abbreviation (e.g. "род.", "ур.") is part of a longer word (e.g. "город.").
func ctxEndIsAbbrevInWord(search string, loc []int) bool {
	ctx := search[loc[0]:loc[1]]
	if !strings.HasSuffix(ctx, ".") {
		return false
	}
	return loc[0] > 0 && isLetterRune(runeBefore(search, loc[0]))
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
	for _, p := range []string{"городе ", "деревне ", "посёлке ", "поселке ", "селе ", "станице ", "кишлаке "} {
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
	// A lowercase place name is accepted too, as long as the first word is not
	// a stop word (e.g. "родился в деревне малые вяземы").
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}
	return !birthStopWords[fields[0]]
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

// bareRegionNames lists Russian republics that are commonly named without a
// "республика"/"область" keyword (e.g. "с. Верхние Киги, Башкирия").
var bareRegionNames = []string{
	"башкирия", "татарстан", "чувашия", "якутия", "дагестан", "ингушетия",
	"осетия", "адыгея", "калмыкия", "мордовия", "удмуртия", "хакасия", "тыва",
	"бурятия", "коми", "карелия", "крым", "марий эл", "кабардино-балкария",
	"карачаево-черкесия", "саха",
}

// isBareRegionName reports whether lower is a known bare Russian republic name
// (see bareRegionNames).
func isBareRegionName(lower string) bool {
	for _, r := range bareRegionNames {
		if lower == r {
			return true
		}
	}
	return false
}

// isRegionTail reports whether s looks like a region/republic tail that follows
// a comma in a birth place (e.g. "Краснодарский край", "Республика
// Башкортостан", "Астраханской обл.", "Башкирия").
func isRegionTail(s string) bool {
	if s == "" {
		return false
	}
	lower := strings.ToLower(strings.Fields(s)[0])
	return isRegionKeyword(lower) || isRegionAdjective(lower) || isBareRegionName(lower)
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

// famousSubjectBefore reports whether the subject immediately before the
// birth-place context at ctxStart is a famous person's name (from famous.txt),
// with no client marker within 30 runes to the left and no other PII in the
// line. When so, the birth place is not personal data and no span is created.
func famousSubjectBefore(t pii.Text, ctxStart int) bool {
	windowStart := subjectWindowStart(t, ctxStart)
	subject := t.Raw[windowStart:ctxStart]
	toks := tokenize(subject)
	if len(toks) == 0 {
		return false
	}
	dict := loadNamesDict()
	// Check the last 2-3 tokens as a famous name sequence (e.g. "Александр
	// Сергеевич Пушкин" or "Лев Толстой").
	for n := 2; n <= 3 && n <= len(toks); n++ {
		seq := toks[len(toks)-n:]
		if !famousSeqMatch(dict, seq) {
			continue
		}
		absStart := windowStart + seq[0].start
		absEnd := windowStart + seq[len(seq)-1].end
		// A client marker or another PII in the line means the name is the
		// client's own, so the birth place is personal data.
		if hasLeftContext(t, absStart, famousSubjectMarkers, 30) {
			return false
		}
		if famousOtherPIISameLine(t, absStart, absEnd) {
			return false
		}
		return true
	}
	return false
}

// subjectWindowStart returns the byte offset of the start of the subject window
// (up to 40 runes) before ctxStart.
func subjectWindowStart(t pii.Text, ctxStart int) int {
	start := ctxStart
	count := 0
	for start > 0 && count < 40 {
		_, size := utf8.DecodeLastRuneInString(t.Raw[:start])
		start -= size
		count++
	}
	return start
}

// famousSeqMatch reports whether the token sequence seq matches a famous
// person's name from the dictionary, ignoring patronymics and initials.
func famousSeqMatch(dict *namesDict, seq []token) bool {
	var stems []string
	for _, tok := range seq {
		lower := strings.ToLower(tok.text)
		// Ignore patronymics and initials: famous persons are matched on
		// name + surname only.
		if isPatronymic(lower) || isInitialToken(lower) {
			continue
		}
		stems = append(stems, normalizeWord(lower))
	}
	for _, f := range dict.famous {
		if sameMultiset(stems, f) {
			return true
		}
	}
	return false
}
