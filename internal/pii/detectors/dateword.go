package detectors

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

// dateWordGenUnits are the genitive ordinal forms of 1-19, used both for the
// day of a date and for the units of a year written in words.
var dateWordGenUnits = []string{
	"первого", "второго", "третьего", "четвёртого", "пятого", "шестого",
	"седьмого", "восьмого", "девятого", "десятого", "одиннадцатого",
	"двенадцатого", "тринадцатого", "четырнадцатого", "пятнадцатого",
	"шестнадцатого", "семнадцатого", "восемнадцатого", "девятнадцатого",
}

// dateWordNomUnits are the nominative ordinal forms of 1-19, used for the day
// of a date.
var dateWordNomUnits = []string{
	"первое", "второе", "третье", "четвёртое", "пятое", "шестое",
	"седьмое", "восьмое", "девятое", "десятое", "одиннадцатое",
	"двенадцатое", "тринадцатое", "четырнадцатое", "пятнадцатое",
	"шестнадцатое", "семнадцатое", "восемнадцатое", "девятнадцатое",
}

// dateWordDays maps a day ordinal (genitive or nominative) to its day number.
var dateWordDays = buildDateWordDays()

// dateWordDayRe matches a day ordinal (genitive or nominative).
var dateWordDayRe = buildDateWordDayRe()

// dateWordYearRe matches a year written in words or as four digits.
var dateWordYearRe = buildDateWordYearRe()

// dateWordsRe matches a full date written in words: day + month + year, with an
// optional "года"/"г."/"г" tail. The day is captured in group 1.
var dateWordsRe = buildDateWordsRe()

// buildDateWordDays builds the day-ordinal to day-number map for 1-31 in both
// the genitive and nominative cases.
func buildDateWordDays() map[string]int {
	m := make(map[string]int)
	for i := 1; i <= 19; i++ {
		m[dateWordGenUnits[i-1]] = i
		m[dateWordNomUnits[i-1]] = i
	}
	m["двадцатого"] = 20
	m["двадцатое"] = 20
	m["тридцатого"] = 30
	m["тридцатое"] = 30
	for i := 1; i <= 9; i++ {
		m["двадцать "+dateWordGenUnits[i-1]] = 20 + i
		m["двадцать "+dateWordNomUnits[i-1]] = 20 + i
	}
	m["тридцать "+dateWordGenUnits[0]] = 31
	m["тридцать "+dateWordNomUnits[0]] = 31
	return m
}

// buildDateWordDayRe builds a regex matching any day ordinal, longest first so
// a compound form ("двадцать первого") wins over its tail ("первого").
func buildDateWordDayRe() *regexp.Regexp {
	keys := make([]string, 0, len(dateWordDays))
	for k := range dateWordDays {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	return regexp.MustCompile(`(?:` + strings.Join(keys, "|") + `)`)
}

// buildDateWordYearRe builds a regex matching a year written in words or as
// four digits. Word years cover 1901-1999 ("тысяча девятьсот ..."), 2000
// ("двухтысячного") and 2001-2019 ("две тысячи ..."). All word forms are
// enumerated explicitly and sorted longest-first so the longest match wins
// (RE2 does not reliably extend an optional group inside an alternation).
func buildDateWordYearRe() *regexp.Regexp {
	tens := []string{
		"двадцатого", "тридцатого", "сорокового", "пятидесятого",
		"шестидесятого", "семидесятого", "восемьдесят", "девяностого",
	}
	var alts []string
	// 1901-1919: тысяча девятьсот + units.
	for _, u := range dateWordGenUnits {
		alts = append(alts, "тысяча девятьсот "+u)
	}
	// 1920-1999: тысяча девятьсот + tens, and + tens + units (1-9).
	for _, t := range tens {
		alts = append(alts, "тысяча девятьсот "+t)
		for _, u := range dateWordGenUnits[:9] {
			alts = append(alts, "тысяча девятьсот "+t+" "+u)
		}
	}
	// 2000: двухтысячного.
	alts = append(alts, "двухтысячного")
	// 2001-2019: две тысячи + units.
	for _, u := range dateWordGenUnits {
		alts = append(alts, "две тысячи "+u)
	}
	sort.Slice(alts, func(i, j int) bool { return len(alts[i]) > len(alts[j]) })
	alts = append(alts, `\d{4}`)
	return regexp.MustCompile(`(?:` + strings.Join(alts, "|") + `)`)
}

// buildDateWordsRe builds the full date-in-words regex. The day is captured in
// group 1 so the validator can reject meaningless days.
func buildDateWordsRe() *regexp.Regexp {
	monthAlt := buildMonthAlt()
	return regexp.MustCompile(
		`(` + dateWordDayRe.String() + `)\s+` + monthAlt + `\s+` + dateWordYearRe.String() +
			`(?:\s+(?:года|г\.|г))?`,
	)
}

// buildMonthAlt builds a regex alternation of the genitive month names and
// abbreviations, longest first.
func buildMonthAlt() string {
	keys := make([]string, 0, len(monthNames))
	for k := range monthNames {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	return `(?:` + strings.Join(keys, "|") + `)`
}

// dateWordDayValid reports whether a day ordinal maps to a day number no
// greater than 31.
func dateWordDayValid(day string) bool {
	n, ok := dateWordDays[day]
	return ok && n <= 31
}

// dateWordRightContexts are the birth-date keywords that may appear to the
// right of a date. The shared BirthContexts cover г.р., г. р., уроженец and
// уроженка; the specific right-context keywords are added on top.
var dateWordRightContexts = append([]string{"года рождения", "р.", "место рождения"}, pii.BirthContexts...)

// dateBirthReclassify applies the birth_date reclassification shared by the
// regex date rule and the dateWords detector. It returns birth_date when a
// birth context keyword appears near the match, otherwise date.
func dateBirthReclassify(t pii.Text, start, end int) pii.Category {
	if ok, _ := leftContext(t, start, 120, pii.BirthContexts); ok {
		return pii.CatBirthDate
	}
	if ok, _ := rightContext(t, end, 40, dateWordRightContexts); ok {
		return pii.CatBirthDate
	}
	return pii.CatDate
}

// dateWordsDetector detects dates written fully in words.
type dateWordsDetector struct {
	re *regexp.Regexp
}

// NewDateWordsDetector builds the date-words detector.
func NewDateWordsDetector() pii.Detector {
	return &dateWordsDetector{re: dateWordsRe}
}

func (d *dateWordsDetector) Name() string { return "datewords" }

func (d *dateWordsDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatDate, pii.CatBirthDate}
}

func (d *dateWordsDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *dateWordsDetector) DetectLower(t pii.Text) []pii.Span {
	search := t.Raw
	if t.LowerOK() {
		search = t.Lower
	}
	var spans []pii.Span
	for _, loc := range d.re.FindAllStringIndex(search, -1) {
		start, end := loc[0], loc[1]
		end = trimTrailingSeparators(t.Raw, start, end)
		if !d.acceptMatch(t, search, start, end) {
			continue
		}
		spans = append(spans, pii.Span{
			Start:      start,
			End:        end,
			Category:   dateBirthReclassify(t, start, end),
			Detector:   d.Name(),
			Confidence: 0.85,
		})
	}
	return spans
}

// acceptMatch reports whether a matched date span passes the boundary and day
// validity checks.
func (d *dateWordsDetector) acceptMatch(t pii.Text, search string, start, end int) bool {
	if !dateWordBoundary(t.Raw, start, end) {
		return false
	}
	if precededByDayTens(search, start) {
		return false
	}
	sub := d.re.FindStringSubmatchIndex(search[start:end])
	if sub == nil || sub[2] < 0 {
		return false
	}
	day := search[start+sub[2] : start+sub[3]]
	return dateWordDayValid(day)
}

// dateWordBoundary reports whether the match is not adjacent to a letter (or,
// after the match, a digit) so a date is not matched inside a longer word or a
// longer digit run.
func dateWordBoundary(raw string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(raw[:start])
		if isLetterRune(r) {
			return false
		}
	}
	if end < len(raw) {
		r, _ := utf8.DecodeRuneInString(raw[end:])
		if isLetterRune(r) || (r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// precededByDayTens reports whether the token immediately before start is
// "двадцать" or "тридцать". This rejects a day ordinal that is the tail of an
// invalid compound day (e.g. "второго" in "тридцать второго марта 1985").
func precededByDayTens(search string, start int) bool {
	if start < 9 {
		return false
	}
	prefix := search[:start]
	for _, tens := range []string{"двадцать ", "тридцать "} {
		if strings.HasSuffix(prefix, tens) {
			return true
		}
	}
	return false
}
