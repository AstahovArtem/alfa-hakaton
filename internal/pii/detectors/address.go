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
	addrIndexRe     = regexp.MustCompile(`\b[1-6]\d{5}\b`)
	addrCountryRe   = regexp.MustCompile(`(?i)(?:российская федерация|республика беларусь|россия|рф|казахстан|беларусь|армения|узбекистан)`)
	addrRegionRe    = regexp.MustCompile(`(?i)(?:\S+\s+(?:область|обл\.|край|республика|респ\.|автономный округ|ао)|(?:республика|респ\.)\s+\S+)`)
	addrDistrictRe  = regexp.MustCompile(`(?i)\S+\s+(?:район|р-н)`)
	addrLocalityRe  = regexp.MustCompile(`(?i)(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт)\s+[А-Яа-яЁё-]+`)
	addrStreetRe    = regexp.MustCompile(`(?i)(?:(?:ул\.|улица|пр-т|пр\.|проспект|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная|пл\.|площадь|проезд|пр-д|тупик|аллея)\s+[А-Яа-яЁё-]+\.?(?:\s+[А-Яа-яЁё-]+\.?){0,2}|[А-Яа-яЁё-]+\s+(?:улица|проспект|переулок|бульвар|шоссе|набережная|площадь|проезд|тупик|аллея))`)
	addrHouseRe     = regexp.MustCompile(`(?i)(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`)
	addrAptRe       = regexp.MustCompile(`(?i)(?:кв\.|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
	addrBareHouseRe = regexp.MustCompile(`,\s*\d+[а-яa-z]?`)
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
	addrLocalityLowerRe = regexp.MustCompile(`(?:г\.|город|гор\.|пос\.|посёлок|поселок|с\.|село|дер\.|деревня|ст\.|станица|пгт)\s+[а-яё-]+`)
	addrStreetLowerRe   = regexp.MustCompile(`(?:(?:ул\.|улица|пр-т|пр\.|проспект|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная|пл\.|площадь|проезд|пр-д|тупик|аллея)\s+[а-яё-]+\.?(?:\s+[а-яё-]+\.?){0,2}|[а-яё-]+\s+(?:улица|проспект|переулок|бульвар|шоссе|набережная|площадь|проезд|тупик|аллея))`)
	addrHouseLowerRe    = regexp.MustCompile(`(?:д\.|дом|д)\s*\d+[а-яa-z]?(?:\s*/\s*\d+)?(?:\s*(?:к\.|корп\.|корпус|к)\s*\d+)?(?:\s*(?:стр\.|строение|с)\s*\d+)?`)
	addrAptLowerRe      = regexp.MustCompile(`(?:кв\.|квартира|оф\.|офис|пом\.|помещение|комн\.)\s*\d+[а-я]?`)
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
	"место жительства", "доставка", "доставить", "живу", "живёт",
}

var addrException = []string{
	"отделение", "офис банка", "банкомат", "филиал", "дополнительный офис",
	"головной офис", "доп. офис", "до",
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
	countryRe, regionRe, districtRe, localityRe, streetRe, houseRe, aptRe :=
		addrCountryRe, addrRegionRe, addrDistrictRe, addrLocalityRe, addrStreetRe, addrHouseRe, addrAptRe
	if t.LowerOK() {
		search = t.Lower
		countryRe, regionRe, districtRe, localityRe, streetRe, houseRe, aptRe =
			addrCountryLowerRe, addrRegionLowerRe, addrDistrictLowerRe, addrLocalityLowerRe, addrStreetLowerRe, addrHouseLowerRe, addrAptLowerRe
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
	add(localityRe, "locality")
	add(streetRe, "street")
	add(houseRe, "house")
	add(aptRe, "apartment")

	// Bare house number following a street (e.g. "ул. Ленина, 5").
	for _, s := range comps {
		if s.kind != "street" {
			continue
		}
		for _, loc := range addrBareHouseRe.FindAllStringIndex(text[s.end:], -1) {
			start := s.end + loc[0]
			end := s.end + loc[1]
			if gapRunes(text, s.end, start) <= 3 {
				comps = append(comps, addrComponent{start: start, end: end, kind: "house"})
			}
		}
	}

	// Locality from the cities dictionary (any case, any position). The text is
	// lowercased once; the dictionary is already lowercase. Cities are indexed
	// by their first two runes so only relevant candidates are checked per
	// position.
	lower := t.Lower
	if !t.LowerOK() {
		lower = strings.ToLower(text)
	}
	cd := loadCities()
	// findLocalities scans lower for every city (and its oblique forms) that
	// shares the two-rune prefix at each position. When includeCity is true the
	// nominative city name itself is also checked.
	findLocalities := func(includeCity, needCtx bool) {
		i := 0
		for i < len(lower) {
			p := firstTwoRunes(lower[i:])
			if p == "" {
				break
			}
			cands := cd.byPrefix[p]
			for _, city := range cands {
				if includeCity && strings.HasPrefix(lower[i:], city) {
					start := i
					end := i + len(city)
					if (start == 0 || !isLetterRune(rune(text[start-1]))) &&
						(end == len(text) || !isLetterRune(rune(text[end]))) {
						comps = append(comps, addrComponent{start: start, end: end, kind: "locality"})
					}
				}
				for _, form := range cd.oblique[city] {
					if !strings.HasPrefix(lower[i:], form) {
						continue
					}
					start := i
					end := i + len(form)
					if (start == 0 || !isLetterRune(rune(text[start-1]))) &&
						(end == len(text) || !isLetterRune(rune(text[end]))) &&
						(!needCtx || hasLeftContext(t, start, addrContext, 30)) {
						comps = append(comps, addrComponent{start: start, end: end, kind: "locality"})
					}
				}
			}
			_, size := utf8.DecodeRuneInString(lower[i:])
			i += size
		}
	}
	// Nominative city names.
	findLocalities(true, false)
	// Oblique-case localities (e.g. "Казани") are accepted only when an address
	// context keyword appears to the left.
	findLocalities(false, true)

	// Bare street + house number following a locality (e.g. "Казани, Кремлёвская 5").
	// A bare street is only accepted inside an already-valid address, so it must
	// attach to a locality component.
	for _, s := range comps {
		if s.kind != "locality" {
			continue
		}
		for _, loc := range addrBareStreetHouseRe.FindAllStringIndex(text[s.end:], -1) {
			start := s.end + loc[0]
			end := s.end + loc[1]
			if gapRunes(text, s.end, start) <= 3 {
				comps = append(comps, addrComponent{start: start, end: end, kind: "street_house"})
			}
		}
	}
	return comps
}

func (d *addressDetector) validGroup(t pii.Text, group []addrComponent) bool {
	hasStreet := false
	hasHouse := false
	hasLocality := false
	hasOther := false
	for _, c := range group {
		switch c.kind {
		case "street":
			hasStreet = true
		case "house":
			hasHouse = true
		case "street_house":
			hasStreet = true
			hasHouse = true
		case "locality":
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

// decodedRune returns the rune at byte position pos in s.
func decodedRune(s string, pos int) rune {
	r, _ := utf8.DecodeRuneInString(s[pos:])
	return r
}

// runeBefore returns the rune that ends at byte position pos in s.
func runeBefore(s string, pos int) rune {
	if pos <= 0 {
		return 0
	}
	i := pos - 1
	for i > 0 && s[i]&0xC0 == 0x80 {
		i--
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r
}

// gapRunes returns the number of runes between byte positions a and b.
func gapRunes(text string, a, b int) int {
	if b <= a {
		return 0
	}
	return utf8.RuneCountInString(text[a:b])
}
