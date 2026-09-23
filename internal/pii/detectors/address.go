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
	kindLabeled     = "labeled"
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
		list := cityList(data)
		sort.Slice(list, func(i, j int) bool {
			return len([]rune(list[i])) > len([]rune(list[j]))
		})
		citiesData = buildCitiesDict(list)
	})
	return citiesData
}

// cityList returns the non-empty, trimmed lines of data.
func cityList(data []byte) []string {
	var list []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			list = append(list, line)
		}
	}
	return list
}

// buildCitiesDict builds the oblique forms and prefix index for a city list.
func buildCitiesDict(list []string) *citiesDict {
	oblique := make(map[string][]string, len(list))
	byPrefix := make(map[string][]string)
	for _, c := range list {
		oblique[c] = obliqueForms(c)
		if p := firstTwoRunes(c); p != "" {
			byPrefix[p] = append(byPrefix[p], c)
		}
	}
	return &citiesDict{cities: list, oblique: oblique, byPrefix: byPrefix}
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
	addrIndexRe   = regexp.MustCompile(`\b[1-6]\d{5}\b`)
	addrCountryRe = regexp.MustCompile(
		`(?i)(?:российская федерация|республика беларусь|россия|рф|казахстан|беларусь|армения|узбекистан)`,
	)
	addrRegionRe = regexp.MustCompile(
		`(?i)(?:\S+\s+(?:область|обл\.|край|автономный округ|ао)|(?:республика|респ\.)\s+\S+)`,
	)
	addrDistrictRe = regexp.MustCompile(`(?i)\S+\s+(?:район|р-н)`)
	addrLocalityRe = regexp.MustCompile(
		`(?i)(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт|мкр\.|микрорайон)\s+[А-Яа-яЁё-]+(?:\s+[А-Яа-яЁё-]+){0,2}`,
	)
	// addrStreetMarkerRe matches a street marker followed by the street name,
	// e.g. "улица Гагарина". It is case-insensitive for the marker.
	addrStreetMarkerRe = regexp.MustCompile(
		`(?i)(?:ул\.|ул|улица|улице|улицу|пр-кт|пр-т|пр\.|проспект|проспекте|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная|пл\.|площадь|проезд|пр-д|тупик|аллея|линия)\s+[А-Яа-яЁё-]+\.?(?:\s+[А-Яа-яЁё-]+\.?){0,2}`,
	)
	// addrStreetNameRe matches a capitalised street name followed by a marker,
	// e.g. "Ленинский проспект". It is case-sensitive so that prepositions like
	// "на" are not captured as street names. It is matched against the raw text.
	addrStreetNameRe = regexp.MustCompile(
		`[А-ЯЁ][а-яё-]+(?:\s+[А-ЯЁ][а-яё-]+){0,1}\s+(?:улица|ул\.|проспект|пр-т|пр\.|переулок|пер\.|бульвар|б-р|шоссе|ш\.|набережная|наб\.|площадь|пл\.|проезд|тупик|аллея|линия)`,
	)
	addrHouseRe = regexp.MustCompile(
		`(?i)(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*-\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`,
	)
	// addrStrRe matches a standalone строение number, e.g. "стр. 1" in
	// "д. 10, стр. 1, кв. 704".
	addrStrRe = regexp.MustCompile(`(?i)(?:стр\.|строение)\s*\d+[а-яa-z]?`)
	addrAptRe = regexp.MustCompile(`(?i)(?:кв\.|кв|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
	// addrAptWordRe matches an apartment whose number is written in words, e.g.
	// "квартира сорок два". The span runs to the end of the phrase.
	addrAptWordRe = regexp.MustCompile(`(?i)(?:кв\.|квартира)\s+[а-яё]+(?:\s+[а-яё]+)?`)
	// addrPOBoxRe matches a post-office box, e.g. "а/я 145".
	addrPOBoxRe = regexp.MustCompile(`(?i)а/я\s*\d+`)
	// addrBareStreetCtxRe matches a bare street name (no marker) followed by a
	// house number and optional корпус/квартира, e.g. "Профсоюзной 96 корпус 2,
	// квартира 15" or "Пушкина, 15, кв. 2". It is only accepted when a housing
	// context keyword appears to the left. The house number is limited to 4
	// digits so long numbers (e.g. order ids) are not attached.
	addrBareStreetCtxRe = regexp.MustCompile(
		`[А-ЯЁ][а-яё-]+(?:\s+[А-ЯЁ][а-яё-]+){0,2}\s*,?\s*\d{1,4}[а-яa-z]?(?:\s+(?:корп\.|корпус|к)\s*\d+)?(?:\s*,\s*(?:кв\.|квартира)\s*\d+[а-я]?)?`,
	)
	// addrBareStreetCtxLowerRe is the lowercase-only variant of
	// addrBareStreetCtxRe, matched against the lowercased text so a lowercase
	// street name (e.g. "проживаю на тверской 5, квартира 8") is captured. The
	// street name must follow a preposition ("на", "в", "по") so the span starts
	// at the street, not at a context keyword. It is only accepted when a housing
	// context keyword appears to the left.
	addrBareStreetCtxLowerRe = regexp.MustCompile(
		`(?:на|в|по)\s+([а-яё-]+(?:\s+[а-яё-]+){0,2}\s*,?\s*\d{1,4}[а-яa-z]?(?:\s+(?:корп\.|корпус|к)\s*\d+)?(?:\s*,\s*(?:кв\.|квартира)\s*\d+[а-я]?)?)`,
	)
	addrBareHouseRe = regexp.MustCompile(`,\s*\d{1,4}[а-яa-z]?(?:\s*-\s*\d+)?`)
	// addrBareHouseDirectRe matches a bare house number directly after a street
	// name with no comma, e.g. "пр. просвещения 87 к1". The optional корпус is
	// included.
	addrBareHouseDirectRe = regexp.MustCompile(`\d{1,4}[а-яa-z]?(?:\s+(?:к\.|корп\.|корпус|к)\s*\d+)?`)
	// addrBareStreetHouseRe matches a bare street name (no marker) followed by a
	// house number, e.g. "Кремлёвская 5". The street name must start with an
	// uppercase letter so common nouns like "паспорт" or "код" are not captured.
	// It is only accepted when attached to a locality, so a bare street never
	// stands alone.
	addrBareStreetHouseRe = regexp.MustCompile(`[А-ЯЁ][а-яё-]+(?:\s+[А-ЯЁ][а-яё-]+){0,2}\s+\d{1,4}[а-яa-z]?`)
	// Lowercase-only variants of the (?i) regexes, matched against the
	// lowercased text to avoid case-folding cost.
	addrCountryLowerRe = regexp.MustCompile(
		`(?:российская федерация|республика беларусь|россия|рф|казахстан|беларусь|армения|узбекистан)`,
	)
	addrRegionLowerRe = regexp.MustCompile(
		`(?:\S+\s+(?:область|обл\.|край|автономный округ|ао)|(?:республика|респ\.)\s+\S+)`,
	)
	addrDistrictLowerRe = regexp.MustCompile(`\S+\s+(?:район|р-н)`)
	addrLocalityLowerRe = regexp.MustCompile(
		`(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт|мкр\.|микрорайон)\s+[а-яё-]+(?:\s+[а-яё-]+){0,2}`,
	)
	addrHouseLowerRe = regexp.MustCompile(
		`(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*-\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`,
	)
	addrStrLowerRe     = regexp.MustCompile(`(?:стр\.|строение)\s*\d+[а-яa-z]?`)
	addrAptLowerRe     = regexp.MustCompile(`(?:кв\.|кв|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
	addrAptWordLowerRe = regexp.MustCompile(`(?:кв\.|квартира)\s+[а-яё]+(?:\s+[а-яё]+)?`)
	addrPOBoxLowerRe   = regexp.MustCompile(`а/я\s*\d+`)
	// addrParenLocalityRe matches a locality in parentheses, e.g. "(Уфа)".
	addrParenLocalityRe = regexp.MustCompile(`\([А-ЯЁ][а-яё-]+\)`)
	// addrLabeledRe matches a labelled address component prefix, e.g. "Страна:",
	// "Индекс:", "Город:", "Улица:", "Дом:", "Квартира:", and also "Страна =",
	// "Страна - " and "Страна — ". The "=" and ":" separators may sit directly
	// against the label (e.g. "city=Москва"); "-"/"—" require surrounding
	// whitespace so a compound word like "дом-музей" is not mistaken for a
	// labelled "Дом" field. The value that follows runs to the next label or
	// the end of the line and is computed in code. The label is matched
	// case-insensitively; the value keeps its original case.
	addrLabeledRe = regexp.MustCompile(
		`(?i)(?:страна проживания|страна|индекс|город|улица|дом|квартира|кв\.|кв|region|country|index|zip|city|street|building|apt)(?:\s*:\s*|\s*=\s*|\s+[-—]\s+)`,
	)
)

// obliqueEndings are the non-nominative case endings appended to a city stem.
var obliqueEndings = []string{"е", "и", "у", sufOy, sufOm, "а", "ы"}

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

// addrExceptionStems are word stems that mark an organisation address (e.g.
// "отделении", "офисе", "банкомат"). A word whose lowercase form starts with a
// stem triggers the exception, so inflected forms like "отделении" and
// "отделения" are covered.
var addrExceptionStems = []string{
	"отделени", "офис", "банкомат", "филиал", "юридическ", "юрадрес", "головн",
	"отель", "гостиниц", "конференц",
}

// bareStreetAdjectiveSuffixes are the adjective endings a lowercase bare street
// name must have (e.g. "тверской", "профсоюзной", "тверская"). A bare street
// name that is not an adjective (e.g. "будний день до 19") is not an address.
var bareStreetAdjectiveSuffixes = []string{
	"ской", sufSkaya, "ая", sufOy, sufIy, "ому", sufOm,
}

// bareStreetStopWords are lowercase words that must not be treated as a bare
// street name even when they precede a number (e.g. "будний день до 19:00").
var bareStreetStopWords = map[string]bool{
	"будний": true, "рабочий": true, "любой": true, "ближайший": true,
	"следующий": true, "этот": true, "каждый": true, "день": true,
	"время": true, "час": true,
}

// bareStreetDurationWords are words that, when they follow the house number of a
// bare street match, mark it as a time/duration phrase rather than an address
// (e.g. "до 19:00", "в 5 часов").
var bareStreetDurationWords = map[string]bool{
	"час": true, "день": true, "до": true,
}

// addrNonStreetWords are capitalised words that must not be treated as a bare
// street name in a street+house pattern (e.g. "Паспорт 5414", "Серия 45 09").
var addrNonStreetWords = map[string]bool{
	ctxPasport: true, "серия": true, "снилс": true, "инн": true,
	"телефон": true, "тел": true, "карта": true, "счёт": true, "счет": true,
	"заказ": true, "договор": true, "код": true, "пин": true, "cvc": true,
	"cvv": true, "выдан": true, "выдано": true, "получатель": true,
	"клиент": true, "оператор": true, "фио": true, "ф.и.о": true,
	"адрес": true, "адресу": true, "адреса": true, "адресе": true, "проживаю": true,
	"проживает": true, "живу": true, "живёт": true, "живет": true, "снимаю": true,
	"прописка": true, "регистрации": true, "регистрация": true,
}

// addrExceptionPhrases are whole-word organisation-address phrases that are not
// covered by a single stem.
var addrExceptionPhrases = []string{
	"пункт выдачи", "адрес банка", "до", "банка", "банке",
}

// addrPersonalMarkers are phrases that mark an address as the client's own.
// When one appears closer to the address than an organisation-address
// exception phrase, it always cancels the exception.
var addrPersonalMarkers = []string{
	"живу", "живёт", "живет", "проживаю", "проживает", "прописан", "прописана",
	"зарегистрирован", "зарегистрирована", "адрес регистрации",
	"адрес проживания", "мой адрес", "домашний адрес", "фактический адрес",
	"прописка",
}

// addrExceptionWindow is the number of runes scanned before an address group
// for an organisation-address exception keyword.
const addrExceptionWindow = 60

// addrClauseBoundary is the set of bytes that end a clause for the purpose of
// binding an organisation-address exception to its direct head.
const addrClauseBoundary = ",.!?\n"

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
	sort.Slice(comps, func(i, j int) bool { return addrComponentLess(comps[i], comps[j]) })

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
		j := groupEnd(t.Raw, kept, i)
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

// addrComponentLess orders components by start, then by longer span, then
// prefers a labelled component on identical spans so the value keeps its label
// context (e.g. "Страна: Россия" beats the bare country "Россия").
func addrComponentLess(a, b addrComponent) bool {
	if a.start != b.start {
		return a.start < b.start
	}
	if a.end != b.end {
		return a.end > b.end
	}
	return a.kind == kindLabeled && b.kind != kindLabeled
}

// groupEnd returns the index of the last component in the group starting at i,
// where adjacent components are separated by at most 3 runes and do not cross a
// sentence boundary.
func groupEnd(text string, kept []addrComponent, i int) int {
	j := i
	for j+1 < len(kept) &&
		gapRunes(text, kept[j].end, kept[j+1].start) <= 3 &&
		!crossesSentenceBoundary(text, kept[j].end, kept[j+1].start) {
		j++
	}
	return j
}

// crossesSentenceBoundary reports whether the text between from and to contains
// a sentence boundary: a newline, "!", "?", or ". " followed by a capital
// letter. The capital letter may sit at to (the start of the next component).
func crossesSentenceBoundary(text string, from, to int) bool {
	seg := text[from:to]
	if strings.ContainsAny(seg, "!?\n") {
		return true
	}
	search := seg
	for {
		i := strings.Index(search, ". ")
		if i < 0 {
			break
		}
		after := from + i + 2
		if after < len(text) {
			r, _ := utf8.DecodeRuneInString(text[after:])
			if isUpperRune(r) {
				return true
			}
		}
		search = search[i+2:]
	}
	return false
}

func (d *addressDetector) findComponents(t pii.Text) []addrComponent {
	text := t.Raw
	// When byte lengths match, match the (?i) regexes against the lowercased
	// text with lowercase-only variants to avoid case-folding cost.
	search := text
	countryRe, regionRe, districtRe, localityRe, houseRe, aptRe, aptWordRe, poBoxRe, strRe :=
		addrCountryRe, addrRegionRe, addrDistrictRe, addrLocalityRe, addrHouseRe, addrAptRe, addrAptWordRe, addrPOBoxRe, addrStrRe
	if t.LowerOK() {
		search = t.Lower
		countryRe, regionRe, districtRe, localityRe, houseRe, aptRe, aptWordRe, poBoxRe, strRe =
			addrCountryLowerRe, addrRegionLowerRe, addrDistrictLowerRe, addrLocalityLowerRe, addrHouseLowerRe, addrAptLowerRe, addrAptWordLowerRe, addrPOBoxLowerRe, addrStrLowerRe
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
	comps = append(comps, findLocalities(search, text, localityRe)...)
	comps = append(comps, findStreets(text)...)
	trimStreetMarkers(text, comps)
	add(houseRe, kindHouse)
	add(strRe, kindHouse)
	add(aptRe, "apartment")
	add(aptWordRe, "apartment")
	add(poBoxRe, "po_box")

	comps = append(comps, bareHousesAfterStreet(text, comps)...)
	comps = append(comps, findDictLocalities(t, text)...)
	comps = append(comps, bareStreetsAfterLocality(text, comps)...)

	comps = append(comps, findBareStreetContext(t, text)...)
	comps = append(comps, findLabeledComponents(text)...)
	return comps
}

// findBareStreetContext finds a bare adjective street + house number with a
// housing context keyword to the left (e.g. "снимаю на Профсоюзной 96 корпус 2,
// квартира 15" and the lowercase "проживаю на тверской 5, квартира 8").
func findBareStreetContext(t pii.Text, text string) []addrComponent {
	var comps []addrComponent
	for _, loc := range addrBareStreetCtxRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if followedByDigit(text, end) {
			continue
		}
		if hasLeftContext(t, start, addrContext, 30) {
			comps = append(comps, addrComponent{start: start, end: end, kind: kindStreetHouse})
		}
	}
	// Lowercase street name variant (e.g. "проживаю на тверской 5, квартира 8").
	comps = append(comps, findBareStreetContextLower(t, text)...)
	return comps
}

// findBareStreetContextLower finds a lowercase bare street + house number with a
// housing context keyword to the left (e.g. "проживаю на тверской 5, квартира
// 8"). Matched against the lowercased text; the span covers the street+house
// capture group.
func findBareStreetContextLower(t pii.Text, text string) []addrComponent {
	var comps []addrComponent
	bareCtxSearch := text
	if t.LowerOK() {
		bareCtxSearch = t.Lower
	}
	for _, loc := range addrBareStreetCtxLowerRe.FindAllStringSubmatchIndex(bareCtxSearch, -1) {
		start, end := loc[2], loc[3]
		if start < 0 {
			continue
		}
		if !bareStreetContextMatchOK(text, bareCtxSearch, start, end) {
			continue
		}
		if hasLeftContext(t, start, addrContext, 30) {
			comps = append(comps, addrComponent{start: start, end: end, kind: kindStreetHouse})
		}
	}
	return comps
}

// bareStreetContextMatchOK reports whether a lowercase bare street+house match
// is a plausible address: not a non-street word, not a time/duration phrase, and
// the street name is an adjective.
func bareStreetContextMatchOK(text, lower string, start, end int) bool {
	if followedByDigit(text, end) {
		return false
	}
	if bareStreetIsNonStreet(text, start) {
		return false
	}
	return bareStreetAdjectiveOK(lower, start, end)
}

// bareStreetAdjectiveOK reports whether a lowercase bare street+house match is a
// plausible adjective street name: the first word must be an adjective ending in
// -ой/-ской/-ская/-ая/-ий/-ому/-ом, must not be a stop word, and the house
// number must not be a time (followed by ":") or a duration word ("час", "день",
// "до").
func bareStreetAdjectiveOK(lower string, start, end int) bool {
	word := nextWord(lower, start)
	if bareStreetStopWords[word] || !hasAdjectiveSuffix(word) {
		return false
	}
	// The house number must not be a time (e.g. "19:00") or a duration word.
	number := lastDigitRun(lower, start, end)
	if number < 0 {
		return false
	}
	after := number + 1
	for after < end && lower[after] == ' ' {
		after++
	}
	if after < len(lower) && lower[after] == ':' {
		return false
	}
	if after < end && bareStreetDurationWords[nextWord(lower, after)] {
		return false
	}
	return true
}

// hasAdjectiveSuffix reports whether word ends with one of the adjective
// suffixes used by Russian street names.
func hasAdjectiveSuffix(word string) bool {
	for _, suf := range bareStreetAdjectiveSuffixes {
		if strings.HasSuffix(word, suf) {
			return true
		}
	}
	return false
}

// lastDigitRun returns the byte offset of the last run of digits within
// [start, end), or -1 when there is none.
func lastDigitRun(s string, start, end int) int {
	pos := -1
	for i := start; i < end; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			pos = i
		}
	}
	return pos
}

// findLabeledComponents finds labelled address components (e.g. "Страна:
// Россия", "Дом: 17/9"). Each label:value pair is a separate address component.
// The span covers only the value, not the label. The value runs from after the
// label to the next label, the end of the line, or a sentence-ending period.
func findLabeledComponents(text string) []addrComponent {
	var comps []addrComponent
	labelLocs := addrLabeledRe.FindAllStringIndex(text, -1)
	for i, loc := range labelLocs {
		start := loc[1]
		end := len(text)
		if i+1 < len(labelLocs) {
			end = labelLocs[i+1][0]
		} else if nl := strings.IndexByte(text[start:], '\n'); nl >= 0 {
			end = start + nl
		}
		start, end = trimLabeledValue(text, start, end)
		if end > start {
			comps = append(comps, addrComponent{start: start, end: end, kind: kindLabeled})
		}
	}
	return comps
}

// trimLabeledValue trims a labelled component value to its meaningful span: it
// stops at a sentence-ending period and trims leading/trailing whitespace, a
// trailing comma, a trailing newline and a trailing period that follows a digit
// (e.g. "Квартира: 12." keeps "12", while "обл." keeps its period).
func trimLabeledValue(text string, start, end int) (int, int) {
	if p := sentenceEndPeriod(text, start, end); p >= 0 {
		end = p
	}
	for start < end && (text[start] == ' ' || text[start] == '\t') {
		start++
	}
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == ',' || text[end-1] == ';' || text[end-1] == '\n') {
		end--
	}
	if end > start && text[end-1] == '.' && end-2 >= start && text[end-2] >= '0' && text[end-2] <= '9' {
		end--
	}
	return start, end
}

// sentenceEndPeriod returns the byte offset of the first period within
// [start, end) that ends a sentence (followed by whitespace and an uppercase
// letter), or -1 when there is none. A period at the end of the text is not a
// sentence end (it may be an abbreviation such as "обл.").
func sentenceEndPeriod(text string, start, end int) int {
	for i := start; i < end; i++ {
		if text[i] != '.' {
			continue
		}
		if i+1 < len(text) && text[i+1] == ' ' && i+2 < end && isUpperRune(decodedRune(text, i+2)) {
			return i
		}
	}
	return -1
}

// findLocalities appends locality components, skipping a settlement prefix that
// is part of a longer word (e.g. "адрес. Реальный" must not match "с. Реальный").
func findLocalities(search, text string, localityRe *regexp.Regexp) []addrComponent {
	var comps []addrComponent
	for _, loc := range localityRe.FindAllStringIndex(search, -1) {
		if loc[0] > 0 && isLetterRune(runeBefore(text, loc[0])) {
			continue
		}
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindLocality})
	}
	return comps
}

// addrNonStreetPhrases are capitalised word+marker phrases that addrStreetNameRe
// would otherwise mistake for a street name, because the marker word ("линия")
// is also used idiomatically (e.g. "горячая линия", a hotline, not a street).
var addrNonStreetPhrases = map[string]bool{
	"горячая линия": true,
}

// addrHotlineFollowWords are words that, right after the "линия" marker, mark
// the phrase as a hotline reference rather than a street name (e.g. "линия
// банка 8 800 ..."), so addrStreetMarkerRe must not treat it as a street.
var addrHotlineFollowWords = map[string]bool{
	"банка": true, "банку": true, "банке": true,
}

// isHotlineLinija reports whether a street-marker match starting with "линия"
// is actually a hotline phrase such as "линия банка" rather than a street
// (e.g. "8-я линия" or "Кожевническая линия" are real streets and are not
// affected, since they do not start with the marker itself).
func isHotlineLinija(matchText string) bool {
	fields := strings.Fields(strings.ToLower(matchText))
	if len(fields) < 2 || fields[0] != "линия" {
		return false
	}
	return addrHotlineFollowWords[fields[1]]
}

// findStreets appends street components. The street regexes are always matched
// against the raw text so the word-before-marker form can require an uppercase
// street name.
func findStreets(text string) []addrComponent {
	var comps []addrComponent
	for _, loc := range addrStreetMarkerRe.FindAllStringIndex(text, -1) {
		// The marker alternatives (e.g. "ул") have no built-in word boundary
		// (Go's \b never matches around Cyrillic letters), so a short marker
		// can start inside a longer word (e.g. "ул" inside "вернул"). Reject
		// a match whose start is not a real word boundary.
		if isLetterRune(runeBefore(text, loc[0])) {
			continue
		}
		if isHotlineLinija(text[loc[0]:loc[1]]) {
			continue
		}
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindStreet})
	}
	for _, loc := range addrStreetNameRe.FindAllStringIndex(text, -1) {
		if addrNonStreetPhrases[strings.ToLower(text[loc[0]:loc[1]])] {
			continue
		}
		comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kindStreet})
	}
	return comps
}

// trimStreetMarkers trims trailing house/apartment markers from street
// components so a house number is not swallowed (e.g. "ул можайское шоссе д 112").
func trimStreetMarkers(text string, comps []addrComponent) {
	for i := range comps {
		if comps[i].kind != kindStreet {
			continue
		}
		comps[i].end = trimStreetMarker(text, comps[i].start, comps[i].end)
	}
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
		out = append(out, bareHousesInWindow(text, s.end, windowEnd, addrBareHouseRe, 3)...)
		// A bare house number directly after the street (no comma), e.g.
		// "пр. просвещения 87 к1". Only accepted when it immediately follows the
		// street (gap of one space).
		out = append(out, bareHousesInWindow(text, s.end, windowEnd, addrBareHouseDirectRe, 1)...)
	}
	return out
}

// bareHousesInWindow finds bare house numbers matching re within [from, windowEnd)
// that are at most maxGap runes after from.
func bareHousesInWindow(text string, from, windowEnd int, re *regexp.Regexp, maxGap int) []addrComponent {
	var out []addrComponent
	for _, loc := range re.FindAllStringIndex(text[from:windowEnd], -1) {
		start := from + loc[0]
		end := from + loc[1]
		if !followedByDigit(text, end) && gapRunes(text, from, start) <= maxGap {
			out = append(out, addrComponent{start: start, end: end, kind: kindHouse})
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
	sc := cityScan{lower: lower, text: text, cd: cd, t: t}
	i := 0
	for i < len(lower) {
		p := firstTwoRunes(lower[i:])
		if p == "" {
			break
		}
		for _, city := range cd.byPrefix[p] {
			comps = append(comps, matchCity(sc, i, city, includeCity, needCtx)...)
		}
		_, size := utf8.DecodeRuneInString(lower[i:])
		i += size
	}
	return comps
}

// cityScan bundles the shared state passed to matchCity.
type cityScan struct {
	lower string
	text  string
	cd    *citiesDict
	t     pii.Text
}

// matchCity checks a city and its oblique forms at position i in lower, appending
// any locality components that are not part of a longer word.
func matchCity(sc cityScan, i int, city string, includeCity, needCtx bool) []addrComponent {
	var comps []addrComponent
	if includeCity && strings.HasPrefix(sc.lower[i:], city) {
		comps = append(comps, localityComponent(sc.text, i, i+len(city), false, sc.t)...)
	}
	for _, form := range sc.cd.oblique[city] {
		if !strings.HasPrefix(sc.lower[i:], form) {
			continue
		}
		comps = append(comps, localityComponent(sc.text, i, i+len(form), needCtx, sc.t)...)
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
			if !followedByDigit(text, end) && gapRunes(text, s.end, start) <= 3 && !bareStreetIsNonStreet(text, start) {
				out = append(out, addrComponent{start: start, end: end, kind: kindStreetHouse})
			}
		}
	}
	return out
}

// bareStreetIsNonStreet reports whether the first word of a bare street+house
// match is a known non-street word (e.g. "Паспорт 5414").
func bareStreetIsNonStreet(text string, start int) bool {
	word := nextWord(text, start)
	return addrNonStreetWords[strings.ToLower(word)]
}

func (d *addressDetector) validGroup(t pii.Text, group []addrComponent) bool {
	flags := classifyGroup(group)
	start := group[0].start
	// A single labelled component (e.g. "Страна: Россия") is an address unless
	// an organisation-address header precedes it in the same or previous
	// sentence (e.g. "Адрес отделения банка. Город: Москва").
	if len(group) == 1 && flags.labeled {
		return !d.hasException(t, start, false)
	}
	if flags.street && flags.house {
		return !d.hasException(t, start, true)
	}
	if flags.locality && (flags.other || flags.street || flags.house) {
		return !d.hasException(t, start, true)
	}
	if hasLeftContext(t, start, addrContext, 30) {
		return !d.hasException(t, start, true)
	}
	return false
}

// groupFlags summarises which component kinds appear in an address group.
type groupFlags struct {
	street   bool
	house    bool
	locality bool
	other    bool
	labeled  bool
}

// classifyGroup scans the components and records which kinds are present.
func classifyGroup(group []addrComponent) groupFlags {
	var f groupFlags
	for _, c := range group {
		switch c.kind {
		case kindStreet:
			f.street = true
		case kindHouse:
			f.house = true
		case kindStreetHouse:
			f.street = true
			f.house = true
		case kindLocality:
			f.locality = true
		case kindLabeled:
			f.labeled = true
		default:
			f.other = true
		}
	}
	return f
}

// hasException reports whether pos sits inside an organisation-address
// context. When clauseBound is true (street+house and locality groups), the
// organisation phrase must be the direct head of the address: it is looked up
// only within the current clause (the text since the last comma or sentence
// end), so an unrelated exception word mentioned earlier in the sentence does
// not suppress a personal address (e.g. "работаю в офисе, живу по адресу ...").
// When clauseBound is false (a single labelled component), the whole
// exception window is scanned so an organisation-address header in the same
// or previous sentence still applies (e.g. "Адрес отделения банка. Город:
// Москва"). Either way, a personal marker (живу, проживаю, ...) that sits
// closer to pos than the organisation phrase always cancels the exception.
func (d *addressDetector) hasException(t pii.Text, pos int, clauseBound bool) bool {
	prefix := runeWindowBefore(t, pos, addrExceptionWindow)
	if clauseBound {
		prefix = lastClause(prefix)
	}
	orgIdx := lastExceptionIndex(prefix)
	if orgIdx < 0 {
		return false
	}
	markerIdx := lastMarkerIndex(prefix)
	return markerIdx < orgIdx
}

// lastClause returns the tail of s after the last clause boundary (",", ".",
// "!", "?", "\n"), or s unchanged when s contains no boundary.
func lastClause(s string) string {
	idx := strings.LastIndexAny(s, addrClauseBoundary)
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// lastExceptionIndex returns the byte offset of the rightmost
// organisation-address exception stem or phrase in s, or -1 when none is
// found. s must already be lowercased.
func lastExceptionIndex(s string) int {
	best := -1
	for _, stem := range addrExceptionStems {
		if idx := lastStemIndex(s, stem); idx > best {
			best = idx
		}
	}
	for _, kw := range addrExceptionPhrases {
		if idx := lastWordIndex(s, kw); idx > best {
			best = idx
		}
	}
	return best
}

// lastMarkerIndex returns the byte offset of the rightmost personal-address
// marker in s, or -1 when none is found. s must already be lowercased.
func lastMarkerIndex(s string) int {
	best := -1
	for _, kw := range addrPersonalMarkers {
		if idx := lastWordIndex(s, kw); idx > best {
			best = idx
		}
	}
	return best
}

// containsStem reports whether any word in s starts with stem. s must already
// be lowercased.
func containsStem(s, stem string) bool {
	return lastStemIndex(s, stem) >= 0
}

// lastStemIndex returns the byte offset of the rightmost word in s that
// starts with stem, or -1 when none is found. s must already be lowercased.
func lastStemIndex(s, stem string) int {
	best := -1
	idx := 0
	for {
		pos := strings.Index(s[idx:], stem)
		if pos < 0 {
			return best
		}
		start := idx + pos
		if start == 0 || !isLetterRune(runeBefore(s, start)) {
			best = start
		}
		idx = start + 1
	}
}

// followedByDigit reports whether the rune at byte position pos in text is a
// digit. It is used to reject a bare house number that is only a prefix of a
// longer number (e.g. "1234" inside "1234567890").
func followedByDigit(text string, pos int) bool {
	if pos >= len(text) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(text[pos:])
	return r >= '0' && r <= '9'
}

// containsWord reports whether kw appears in s as a whole word.
func containsWord(s, kw string) bool {
	return lastWordIndex(s, kw) >= 0
}

// lastWordIndex returns the byte offset of the rightmost whole-word occurrence
// of kw in s, or -1 when none is found.
func lastWordIndex(s, kw string) int {
	best := -1
	idx := 0
	for {
		pos := strings.Index(s[idx:], kw)
		if pos < 0 {
			return best
		}
		start := idx + pos
		end := start + len(kw)
		leftOK := start == 0 || !isLetterRune(runeBefore(s, start))
		rightOK := end == len(s) || !isLetterRune(decodedRune(s, end))
		if leftOK && rightOK {
			best = start
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
	default:
		return end
	}
}
