package detectors

import (
	"embed"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

//go:embed dict/cities.txt
var citiesFS embed.FS

// Address component kinds.
const (
	kindStreet      = "street"
	kindHouse       = "house"
	kindStreetHouse = "street_house"
	kindLocality    = "locality"
)

// Street markers that introduce a house number.
const (
	markerKorp = "корп"
	markerStr  = "стр"
)

// Region words.
const (
	wordGorod = "гор"
	wordKrai  = "край"
	wordRaion = "район"
)

// addrComponent is a single address fragment with its byte span and kind.
type addrComponent struct {
	start, end int
	kind       string
}

var (
	citiesOnce sync.Once
	citiesData *citiesDict
)

// citiesDict holds the loaded city dictionary with precomputed oblique forms.
type citiesDict struct {
	cities  []string
	oblique map[string][]string
	// byPrefix maps the first two runes of a city to the cities sharing them,
	// so locality search only checks relevant candidates per position.
	byPrefix map[string][]string
}

func loadCities() *citiesDict {
	citiesOnce.Do(func() {
		data, err := citiesFS.ReadFile("dict/cities.txt")
		if err != nil {
			citiesData = &citiesDict{}
			return
		}
		var list []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				list = append(list, line)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return len([]rune(list[i])) > len([]rune(list[j]))
		})
		oblique := make(map[string][]string, len(list))
		byPrefix := make(map[string][]string)
		for _, c := range list {
			oblique[c] = obliqueForms(c)
			if p := firstTwoRunes(c); p != "" {
				byPrefix[p] = append(byPrefix[p], c)
			}
		}
		citiesData = &citiesDict{cities: list, oblique: oblique, byPrefix: byPrefix}
	})
	return citiesData
}

// firstTwoRunes returns the first two runes of s as a string, or "" if s has
// fewer than two runes.
func firstTwoRunes(s string) string {
	i := 0
	for count := 0; count < 2 && i < len(s); count++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

var (
	addrIndexRe    = regexp.MustCompile(`\b[1-6]\d{5}\b`)
	addrCountryRe  = regexp.MustCompile(`(?i)(?:российская федерация|республика беларусь|россия|рф|казахстан|беларусь|армения|узбекистан)`)
	addrRegionRe   = regexp.MustCompile(`(?i)(?:\S+\s+(?:область|обл\.|край|республика|респ\.|автономный округ|ао)|(?:республика|респ\.)\s+\S+)`)
	addrDistrictRe = regexp.MustCompile(`(?i)\S+\s+(?:район|р-н)`)
	addrLocalityRe = regexp.MustCompile(`(?i)(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт)\s+[А-Яа-яЁё-]+(?:\s+[А-Яа-яЁё-]+){0,2}`)
	// addrStreetMarkerRe matches a street marker followed by the street name,
	// e.g. "улица Гагарина". It is case-insensitive for the marker.
	addrStreetMarkerRe = regexp.MustCompile(`(?i)(?:ул\.|ул|улица|улице|улицу|пр-т|пр\.|проспект|проспекте|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная|пл\.|площадь|проезд|пр-д|тупик|аллея|линия)\s+[А-Яа-яЁё-]+\.?(?:\s+[А-Яа-яЁё-]+\.?){0,2}`)
	// addrStreetNameRe matches a capitalised street name followed by a marker,
	// e.g. "Ленинский проспект". It is case-sensitive so that prepositions like
	// "на" are not captured as street names. It is matched against the raw text.
	addrStreetNameRe = regexp.MustCompile(`[А-ЯЁ][а-яё-]+\s+(?:улица|ул\.|проспект|пр-т|пр\.|переулок|пер\.|бульвар|б-р|шоссе|ш\.|набережная|наб\.|площадь|пл\.|проезд|тупик|аллея|линия)`)
	addrHouseRe      = regexp.MustCompile(`(?i)(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*-\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`)
	addrAptRe        = regexp.MustCompile(`(?i)(?:кв\.|кв|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
	// addrAptWordRe matches an apartment whose number is written in words, e.g.
	// "квартира сорок два". The span runs to the end of the phrase.
	addrAptWordRe = regexp.MustCompile(`(?i)(?:кв\.|квартира)\s+[а-яё]+(?:\s+[а-яё]+)?`)
	// addrPOBoxRe matches a post-office box, e.g. "а/я 145".
	addrPOBoxRe = regexp.MustCompile(`(?i)а/я\s*\d+`)
	// addrBareStreetCtxRe matches a bare street name (no marker) followed by a
	// house number and optional корпус/квартира, e.g. "Профсоюзной 96 корпус 2,
	// квартира 15" or "Пушкина, 15, кв. 2". It is only accepted when a housing
	// context keyword appears to the left.
	addrBareStreetCtxRe = regexp.MustCompile(`[А-ЯЁ][а-яё-]+(?:\s+[А-ЯЁ][а-яё-]+){0,2}\s*,?\s*\d+[а-яa-z]?(?:\s+(?:корп\.|корпус|к)\s*\d+)?(?:\s*,\s*(?:кв\.|квартира)\s*\d+[а-я]?)?`)
	addrBareHouseRe     = regexp.MustCompile(`,\s*\d+[а-яa-z]?(?:\s*-\s*\d+)?`)
	// addrBareStreetHouseRe matches a bare street name (no marker) followed by a
	// house number, e.g. "Кремлёвская 5". The street name must start with an
	// uppercase letter so common nouns like "паспорт" or "код" are not captured.
	// It is only accepted when attached to a locality, so a bare street never
	// stands alone.
	addrBareStreetHouseRe = regexp.MustCompile(`[А-ЯЁ][а-яё-]+(?:\s+[А-ЯЁ][а-яё-]+){0,2}\s+\d+[а-яa-z]?`)
	// Lowercase-only variants of the (?i) regexes, matched against the
	// lowercased text to avoid case-folding cost.
	addrCountryLowerRe  = regexp.MustCompile(`(?:российская федерация|республика беларусь|россия|рф|казахстан|беларусь|армения|узбекистан)`)
	addrRegionLowerRe   = regexp.MustCompile(`(?:\S+\s+(?:область|обл\.|край|республика|респ\.|автономный округ|ао)|(?:республика|респ\.)\s+\S+)`)
	addrDistrictLowerRe = regexp.MustCompile(`\S+\s+(?:район|р-н)`)
	addrLocalityLowerRe = regexp.MustCompile(`(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт)\s+[а-яё-]+(?:\s+[а-яё-]+){0,2}`)
	addrHouseLowerRe    = regexp.MustCompile(`(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*-\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`)
	addrAptLowerRe      = regexp.MustCompile(`(?:кв\.|кв|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
	addrAptWordLowerRe  = regexp.MustCompile(`(?:кв\.|квартира)\s+[а-яё]+(?:\s+[а-яё]+)?`)
	addrPOBoxLowerRe    = regexp.MustCompile(`а/я\s*\d+`)
	// addrParenLocalityRe matches a locality in parentheses, e.g. "(Уфа)".
	addrParenLocalityRe = regexp.MustCompile(`\([А-ЯЁ][а-яё-]+\)`)
)

// obliqueEndings are the non-nominative case endings appended to a city stem.
var obliqueEndings = []string{"е", "и", "у", "ой", "ом", "а", "ы"}

// obliqueForms returns candidate oblique (non-nominative) forms of a city name
// built from its stem plus the oblique endings.
func obliqueForms(city string) []string {
	r := []rune(city)
	if len(r) == 0 {
		return nil
	}
	last := r[len(r)-1]
	var stems []string
	switch last {
	case 'а', 'я', 'ь', 'й':
		stems = append(stems, string(r[:len(r)-1]))
	case 'о', 'е':
		stems = append(stems, string(r))
	default:
		stems = append(stems, string(r))
	}
	var forms []string
	for _, stem := range stems {
		for _, e := range obliqueEndings {
			f := stem + e
			// Skip the nominative form itself; only true oblique forms are wanted.
			if f != city {
				forms = append(forms, f)
			}
		}
	}
	return forms
}

var addrContext = []string{
	"адрес", "проживает", "прописан", "зарегистрирован", "проживающий",
	"место жительства", "доставка", "доставить", "живу", "живёт", "снимаю",
	"проживаю", "прописка", "почтовый адрес",
}

var addrException = []string{
	"отделение", "офис банка", "банкомат", "филиал", "дополнительный офис",
	"головной офис", "доп. офис", "до", "офис", "наш офис", "юридический адрес",
	"юрадрес", "адрес банка", "пункт выдачи",
}

type addressDetector struct{}

// NewAddressDetector builds the address detector.
func NewAddressDetector() pii.Detector {
	return &addressDetector{}
}

func (d *addressDetector) Name() string { return "address" }

func (d *addressDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatAddress}
}

func (d *addressDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *addressDetector) DetectLower(t pii.Text) []pii.Span {
	comps := d.findComponents(t)
	if len(comps) == 0 {
		return nil
	}
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].start != comps[j].start {
			return comps[i].start < comps[j].start
		}
		return comps[i].end > comps[j].end
	})

	// Drop overlapping components, keeping the longer one.
	var kept []addrComponent
	for _, c := range comps {
		if len(kept) > 0 && c.start < kept[len(kept)-1].end {
			continue
		}
		kept = append(kept, c)
	}

	// Group adjacent components into candidate spans.
	var spans []pii.Span
	i := 0
	for i < len(kept) {
		j := i
		for j+1 < len(kept) && gapRunes(t.Raw, kept[j].end, kept[j+1].start) <= 3 {
			j++
		}
		group := kept[i : j+1]
		if d.validGroup(t, group) {
			spans = append(spans, pii.Span{
				Start:      group[0].start,
				End:        group[len(group)-1].end,
				Category:   pii.CatAddress,
				Detector:   d.Name(),
				Confidence: 0.9,
			})
		}
		i = j + 1
	}
	return spans
}

func (d *addressDetector) findComponents(t pii.Text) []addrComponent {
	text := t.Raw
	// When byte lengths match, match the (?i) regexes against the lowercased
	// text with lowercase-only variants to avoid case-folding cost.
	search := text
	countryRe, regionRe, districtRe, localityRe, houseRe, aptRe, aptWordRe, poBoxRe :=
		addrCountryRe, addrRegionRe, addrDistrictRe, addrLocalityRe, addrHouseRe, addrAptRe, addrAptWordRe, addrPOBoxRe
	if t.LowerOK() {
		search = t.Lower
		countryRe, regionRe, districtRe, localityRe, houseRe, aptRe, aptWordRe, poBoxRe =
			addrCountryLowerRe, addrRegionLowerRe, addrDistrictLowerRe, addrLocalityLowerRe, addrHouseLowerRe, addrAptLowerRe, addrAptWordLowerRe, addrPOBoxLowerRe
	}
	var comps []addrComponent
	add := func(re *regexp.Regexp, kind string) {
		for _, loc := range re.FindAllStringIndex(search, -1) {
			comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kind})
		}
	}
	add(addrIndexRe, "index")
	add(countryRe, "country")
	add(regionRe, "region")
	add(districtRe, "district")
	// Locality regexes must not match a settlement prefix that is part of a
	// longer word (e.g. "адрес. Реальный" must not match "с. Реальный").
	for _, loc := range localityRe.FindAllStringIndex(search, -1) {
		if loc[0] > 0 && isLetterRune(runeBefore(text, loc[0])) {
			continue
		}
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindLocality})
	}
	// The street regexes are always matched against the raw text so the
	// word-before-marker form can require an uppercase street name.
	for _, loc := range addrStreetMarkerRe.FindAllStringIndex(text, -1) {
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindStreet})
	}
	for _, loc := range addrStreetNameRe.FindAllStringIndex(text, -1) {
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindStreet})
	}
	// Trim trailing house/apartment markers from street components so a house
	// number is not swallowed (e.g. "ул можайское шоссе д 112").
	for i := range comps {
		if comps[i].kind != kindStreet {
			continue
		}
		comps[i].end = trimStreetMarker(text, comps[i].start, comps[i].end)
	}
	add(houseRe, kindHouse)
	add(aptRe, "apartment")
	add(aptWordRe, "apartment")
	add(poBoxRe, "po_box")

	comps = append(comps, bareHousesAfterStreet(text, comps)...)
	comps = append(comps, findDictLocalities(t, text)...)
	comps = append(comps, bareStreetsAfterLocality(text, comps)...)

	// Bare adjective street + house number with a housing context keyword to the
	// left (e.g. "снимаю на Профсоюзной 96 корпус 2, квартира 15").
	for _, loc := range addrBareStreetCtxRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if hasLeftContext(t, start, addrContext, 30) {
			comps = append(comps, addrComponent{start: start, end: end, kind: kindStreetHouse})
		}
	}
	return comps
}

// bareHousesAfterStreet finds bare house numbers following a street component
// (e.g. "ул. Ленина, 5"). The search is limited to a window of 200 runes after
// the street so the cost stays linear in the number of streets.
func bareHousesAfterStreet(text string, comps []addrComponent) []addrComponent {
	var out []addrComponent
	for _, s := range comps {
		if s.kind != kindStreet {
			continue
		}
		windowEnd := runeOffsetAfter(text, s.end, 200)
		for _, loc := range addrBareHouseRe.FindAllStringIndex(text[s.end:windowEnd], -1) {
			start := s.end + loc[0]
			end := s.end + loc[1]
			if gapRunes(text, s.end, start) <= 3 {
				out = append(out, addrComponent{start: start, end: end, kind: kindHouse})
			}
		}
	}
	return out
}

// findDictLocalities finds localities from the cities dictionary (any case, any
// position). The text is lowercased once; the dictionary is already lowercase.
// Cities are indexed by their first two runes so only relevant candidates are
// checked per position.
func findDictLocalities(t pii.Text, text string) []addrComponent {
	lower := t.Lower
	if !t.LowerOK() {
		lower = strings.ToLower(text)
	}
	cd := loadCities()
	var comps []addrComponent
	// Nominative city names.
	comps = append(comps, scanLocalities(lower, text, cd, true, false, t)...)
	// Oblique-case localities (e.g. "Казани") are accepted only when an address
	// context keyword appears to the left.
	comps = append(comps, scanLocalities(lower, text, cd, false, true, t)...)

	// Parenthesised locality, e.g. "(Уфа)".
	for _, loc := range addrParenLocalityRe.FindAllStringIndex(text, -1) {
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindLocality})
	}
	return comps
}

// scanLocalities scans lower for every city (and its oblique forms) that shares
// the two-rune prefix at each position. When includeCity is true the nominative
// city name itself is also checked.
func scanLocalities(lower, text string, cd *citiesDict, includeCity, needCtx bool, t pii.Text) []addrComponent {
	var comps []addrComponent
	i := 0
	for i < len(lower) {
		p := firstTwoRunes(lower[i:])
		if p == "" {
			break
		}
		for _, city := range cd.byPrefix[p] {
			comps = append(comps, matchCity(lower, text, cd, i, city, includeCity, needCtx, t)...)
		}
		_, size := utf8.DecodeRuneInString(lower[i:])
		i += size
	}
	return comps
}

// matchCity checks a city and its oblique forms at position i in lower, appending
// any locality components that are not part of a longer word.
func matchCity(lower, text string, cd *citiesDict, i int, city string, includeCity, needCtx bool, t pii.Text) []addrComponent {
	var comps []addrComponent
	if includeCity && strings.HasPrefix(lower[i:], city) {
		comps = append(comps, localityComponent(text, i, i+len(city), false, t)...)
	}
	for _, form := range cd.oblique[city] {
		if !strings.HasPrefix(lower[i:], form) {
			continue
		}
		comps = append(comps, localityComponent(text, i, i+len(form), needCtx, t)...)
	}
	return comps
}

// localityComponent builds a locality component for the byte range [start,end)
// when it is not part of a longer word and, when needCtx is set, an address
// context keyword appears to the left.
func localityComponent(text string, start, end int, needCtx bool, t pii.Text) []addrComponent {
	if start > 0 && isLetterRune(rune(text[start-1])) {
		return nil
	}
	if end < len(text) && isLetterRune(rune(text[end])) {
		return nil
	}
	if needCtx && !hasLeftContext(t, start, addrContext, 30) {
		return nil
	}
	return []addrComponent{{start: start, end: end, kind: kindLocality}}
}

// bareStreetsAfterLocality finds a bare street + house number following a
// locality (e.g. "Казани, Кремлёвская 5"). A bare street is only accepted
// inside an already-valid address, so it must attach to a locality component.
// The search is limited to a window of 200 runes after the locality so the
// cost stays linear in the number of localities rather than quadratic in the
// text length.
func bareStreetsAfterLocality(text string, comps []addrComponent) []addrComponent {
	var out []addrComponent
	for _, s := range comps {
		if s.kind != kindLocality {
			continue
		}
		windowEnd := runeOffsetAfter(text, s.end, 200)
		for _, loc := range addrBareStreetHouseRe.FindAllStringIndex(text[s.end:windowEnd], -1) {
			start := s.end + loc[0]
			end := s.end + loc[1]
			if gapRunes(text, s.end, start) <= 3 {
				out = append(out, addrComponent{start: start, end: end, kind: kindStreetHouse})
			}
		}
	}
	return out
}

func (d *addressDetector) validGroup(t pii.Text, group []addrComponent) bool {
	hasStreet := false
	hasHouse := false
	hasLocality := false
	hasOther := false
	for _, c := range group {
		switch c.kind {
		case kindStreet:
			hasStreet = true
		case kindHouse:
			hasHouse = true
		case kindStreetHouse:
			hasStreet = true
			hasHouse = true
		case kindLocality:
			hasLocality = true
		default:
			hasOther = true
		}
	}
	start := group[0].start
	if hasStreet && hasHouse {
		return !d.hasException(t, start)
	}
	if hasLocality && (hasOther || hasStreet || hasHouse) {
		return !d.hasException(t, start)
	}
	if hasLeftContext(t, start, addrContext, 30) {
		return !d.hasException(t, start)
	}
	return false
}

func (d *addressDetector) hasException(t pii.Text, pos int) bool {
	prefix := runeWindowBefore(t, pos, 40)
	for _, kw := range addrException {
		if containsWord(prefix, kw) {
			return true
		}
	}
	return false
}

// containsWord reports whether kw appears in s as a whole word.
func containsWord(s, kw string) bool {
	idx := 0
	for {
		pos := strings.Index(s[idx:], kw)
		if pos < 0 {
			return false
		}
		start := idx + pos
		end := start + len(kw)
		leftOK := start == 0 || !isLetterRune(runeBefore(s, start))
		rightOK := end == len(s) || !isLetterRune(decodedRune(s, end))
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
	}
}

// trimStreetMarker trims a trailing house/apartment marker (e.g. "д", "дом",
// "к", "корп", "стр") from a street component so the following house number is
// not swallowed by the street span.
func trimStreetMarker(text string, start, end int) int {
	words := strings.Fields(text[start:end])
	if len(words) == 0 {
		return end
	}
	last := strings.ToLower(strings.TrimRight(words[len(words)-1], "."))
	switch last {
	case "д", "дом", "к", markerKorp, "корпус", markerStr, "строение":
		// Trim the last word.
		cut := end
		for cut > start && text[cut-1] != ' ' {
			cut--
		}
		return cut
	}
	return end
}
