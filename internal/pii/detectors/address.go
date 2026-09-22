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
	citiesList []string
)

func loadCities() []string {
	citiesOnce.Do(func() {
		data, err := citiesFS.ReadFile("dict/cities.txt")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				citiesList = append(citiesList, line)
			}
		}
		sort.Slice(citiesList, func(i, j int) bool {
			return len([]rune(citiesList[i])) > len([]rune(citiesList[j]))
		})
	})
	return citiesList
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
	comps := d.findComponents(text)
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
		for j+1 < len(kept) && gapRunes(text, kept[j].end, kept[j+1].start) <= 3 {
			j++
		}
		group := kept[i : j+1]
		if d.validGroup(text, group) {
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

func (d *addressDetector) findComponents(text string) []addrComponent {
	var comps []addrComponent
	add := func(re *regexp.Regexp, kind string) {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			comps = append(comps, addrComponent{start: loc[0], end: loc[1], kind: kind})
		}
	}
	add(addrIndexRe, "index")
	add(addrCountryRe, "country")
	add(addrRegionRe, "region")
	add(addrDistrictRe, "district")
	add(addrLocalityRe, "locality")
	add(addrStreetRe, "street")
	add(addrHouseRe, "house")
	add(addrAptRe, "apartment")

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

	// Locality from the cities dictionary (any case, any position).
	for _, city := range loadCities() {
		lower := strings.ToLower(text)
		cl := strings.ToLower(city)
		idx := 0
		for {
			pos := strings.Index(lower[idx:], cl)
			if pos < 0 {
				break
			}
			start := idx + pos
			end := start + len(city)
			// Require word boundaries.
			if (start == 0 || !isLetterRune(rune(text[start-1]))) &&
				(end == len(text) || !isLetterRune(rune(text[end]))) {
				comps = append(comps, addrComponent{start: start, end: end, kind: "locality"})
			}
			idx = start + len(city)
		}
	}

	// Oblique-case localities (e.g. "Казани") are accepted only when an address
	// context keyword appears to the left.
	for _, city := range loadCities() {
		for _, form := range obliqueForms(city) {
			lower := strings.ToLower(text)
			fl := strings.ToLower(form)
			idx := 0
			for {
				pos := strings.Index(lower[idx:], fl)
				if pos < 0 {
					break
				}
				start := idx + pos
				end := start + len(form)
				if (start == 0 || !isLetterRune(rune(text[start-1]))) &&
					(end == len(text) || !isLetterRune(rune(text[end]))) &&
					hasLeftContext(text, start, addrContext, 30) {
					comps = append(comps, addrComponent{start: start, end: end, kind: "locality"})
				}
				idx = start + len(form)
			}
		}
	}

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

func (d *addressDetector) validGroup(text string, group []addrComponent) bool {
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
		return !d.hasException(text, start)
	}
	if hasLocality && (hasOther || hasStreet || hasHouse) {
		return !d.hasException(text, start)
	}
	if hasLeftContext(text, start, addrContext, 30) {
		return !d.hasException(text, start)
	}
	return false
}

func (d *addressDetector) hasException(text string, pos int) bool {
	prefix := text[:pos]
	r := []rune(prefix)
	if len(r) > 40 {
		prefix = string(r[len(r)-40:])
	}
	lower := strings.ToLower(prefix)
	for _, kw := range addrException {
		if containsWord(lower, kw) {
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
