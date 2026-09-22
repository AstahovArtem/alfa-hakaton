package mask

import (
	"embed"
	"hash/fnv"
	// math/rand: deterministic fake values seeded by the input, not used for security.
	"math/rand"
	"strings"
	"sync"
	"unicode/utf8"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/synth"
)

//go:embed dict/*.txt
var synthFS embed.FS

// Strategy name.
const strategySynthetic = "synthetic"

// Russian surname suffixes used to build feminine forms.
const (
	sufOv  = "ов"
	sufEv  = "ев"
	sufYov = "ёв"
	sufIn  = "ин"
	sufYn  = "ын"
)

// Date tail abbreviations.
const (
	dateTailGoda = "года"
	dateTailG    = "г."
)

// Patronymic names (masculine).
const (
	patrAlexandrovich   = "Александрович"
	patrAndreevich      = "Андреевич"
	patrBorisovich      = "Борисович"
	patrVasilievich     = "Васильевич"
	patrViktorovich     = "Викторович"
	patrVladimirovich   = "Владимирович"
	patrDmitrievich     = "Дмитриевич"
	patrEvgenievich     = "Евгеньевич"
	patrIvanovich       = "Иванович"
	patrIgorevich       = "Игоревич"
	patrKonstantinovich = "Константинович"
	patrMikhailovich    = "Михайлович"
	patrNikolaevich     = "Николаевич"
	patrOlegovich       = "Олегович"
	patrPavlovich       = "Павлович"
	patrPetrovich       = "Петрович"
	patrSergeevich      = "Сергеевич"
	patrFedorovich      = "Фёдорович"
	patrYurievich       = "Юрьевич"
)

// Patronymic names (feminine).
const (
	patrAlexandrovna   = "Александровна"
	patrAndreevna      = "Андреевна"
	patrBorisovna      = "Борисовна"
	patrVasilievna     = "Васильевна"
	patrViktorovna     = "Викторовна"
	patrVladimirovna   = "Владимировна"
	patrDmitrievna     = "Дмитриевна"
	patrEvgenievna     = "Евгеньевна"
	patrIvanovna       = "Ивановна"
	patrIgorevna       = "Игоревна"
	patrKonstantinovna = "Константиновна"
	patrMikhailovna    = "Михайловна"
	patrNikolaevna     = "Николаевна"
	patrOlegovna       = "Олеговна"
	patrPavlovna       = "Павловна"
	patrPetrovna       = "Петровна"
	patrSergeevna      = "Сергеевна"
	patrFedorovna      = "Фёдоровна"
	patrYurievna       = "Юрьевна"
)

// Month names in the genitive case.
const (
	monthJanuary   = "января"
	monthFebruary  = "февраля"
	monthMarch     = "марта"
	monthApril     = "апреля"
	monthMay       = "мая"
	monthJune      = "июня"
	monthJuly      = "июля"
	monthAugust    = "августа"
	monthSeptember = "сентября"
	monthOctober   = "октября"
	monthNovember  = "ноября"
	monthDecember  = "декабря"
)

// syntheticStrategy produces plausible fake values of the same format,
// deterministically derived from the value (seed = FNV-64 of category+value).
type syntheticStrategy struct {
	names    []string
	surnames []string
	patrM    []string
	patrF    []string
	loadOnce sync.Once
}

// NewSynthetic builds the synthetic strategy.
func NewSynthetic() Strategy {
	return &syntheticStrategy{}
}

func (s *syntheticStrategy) Name() string { return strategySynthetic }

func (s *syntheticStrategy) load() {
	s.loadOnce.Do(func() {
		s.names = readSynthDict("dict/first_names.txt")
		s.surnames = readSynthDict("dict/surnames.txt")
		s.patrM = []string{patrAlexandrovich, patrAndreevich, patrBorisovich, patrVasilievich, patrViktorovich,
			patrVladimirovich, patrDmitrievich, patrEvgenievich, patrIvanovich, patrIgorevich, patrKonstantinovich,
			patrMikhailovich, patrNikolaevich, patrOlegovich, patrPavlovich, patrPetrovich, patrSergeevich, patrFedorovich, patrYurievich}
		s.patrF = []string{patrAlexandrovna, patrAndreevna, patrBorisovna, patrVasilievna, patrViktorovna,
			patrVladimirovna, patrDmitrievna, patrEvgenievna, patrIvanovna, patrIgorevna, patrKonstantinovna,
			patrMikhailovna, patrNikolaevna, patrOlegovna, patrPavlovna, patrPetrovna, patrSergeevna, patrFedorovna, patrYurievna}
	})
}

func readSynthDict(path string) []string {
	data, err := synthFS.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (s *syntheticStrategy) Mask(value string, cat pii.Category, doc *DocState) string {
	if doc != nil {
		if m := doc.Memo(value); m != "" {
			return m
		}
	}
	s.load()
	rng := newSeeded(cat, value)
	var out string
	switch cat {
	case pii.CatFullName:
		out = s.synthName(value, rng)
	case pii.CatPhone:
		out = synthPhone(value, rng)
	case pii.CatCardNumber:
		out = synthCard(value, rng)
	case pii.CatINN:
		out = synthINN(value, rng)
	case pii.CatSNILS:
		out = synthSNILS(value, rng)
	case pii.CatPassport:
		out = synthPassport(value, rng)
	case pii.CatDate, pii.CatBirthDate, pii.CatPassportDate:
		out = synthDate(value, rng)
	case pii.CatEmail:
		out = synthEmail(value, rng)
	default:
		out = tokenFallback(value, cat, doc)
	}
	if doc != nil {
		doc.Remember(value, out)
	}
	return out
}

// newSeeded returns a deterministic RNG seeded from category+value.
func newSeeded(cat pii.Category, value string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(string(cat)))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return rand.New(rand.NewSource(int64(h.Sum64())))
}

// tokenFallback produces a [CATEGORY_N] token for categories without a
// dedicated synthetic generator.
func tokenFallback(value string, cat pii.Category, doc *DocState) string {
	if doc != nil {
		if m := doc.Memo(value); m != "" {
			return m
		}
	}
	n := 0
	if doc != nil {
		n = doc.Next(cat)
	}
	repl := "[" + strings.ToUpper(string(cat)) + "_" + itoa(n) + "]"
	if doc != nil {
		doc.Remember(value, repl)
	}
	return repl
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// synthName builds a fake full name preserving the number of words and the
// gender inferred from the patronymic/surname ending.
func (s *syntheticStrategy) synthName(value string, rng *rand.Rand) string {
	words := strings.Fields(value)
	if len(words) == 0 {
		return value
	}
	female := isFemaleName(value)
	first := s.names[rng.Intn(len(s.names))]
	surname := s.surnames[rng.Intn(len(s.surnames))]
	if female {
		surname = feminize(surname)
	}
	patr := s.patrM[rng.Intn(len(s.patrM))]
	if female {
		patr = s.patrF[rng.Intn(len(s.patrF))]
	}
	first = capitalize(first)
	surname = capitalize(surname)
	switch len(words) {
	case 1:
		return surname
	case 2:
		return surname + " " + first
	default:
		return surname + " " + first + " " + patr
	}
}

// isFemaleName guesses gender from the patronymic or surname ending.
func isFemaleName(value string) bool {
	words := strings.Fields(value)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	lower := strings.ToLower(last)
	for _, suf := range []string{"овна", "евна", "ична", "инична"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	for _, suf := range []string{"ова", "ева", "ёва", "ина", "ына", "ская", "цкая"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

// feminize turns a masculine surname into its feminine form.
func feminize(s string) string {
	lower := strings.ToLower(s)
	for _, suf := range []string{sufOv, sufEv, sufYov, sufIn, sufYn} {
		if strings.HasSuffix(lower, suf) {
			return s[:len(s)-len(suf)] + suf + "а"
		}
	}
	return s
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	first, size := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(first)) + s[size:]
}

// synthPhone replaces the digits after "+7 9" keeping the original separators.
func synthPhone(value string, rng *rand.Rand) string {
	digits := digitsOnly(value)
	if len(digits) != 11 {
		return value
	}
	return applyDigits(value, synth.Phone(rng))
}

// synthCard builds a 16-digit card with a valid Luhn and a 4xxx/5xxx BIN,
// keeping the original separators.
func synthCard(value string, rng *rand.Rand) string {
	digits := digitsOnly(value)
	if len(digits) < 13 || len(digits) > 19 {
		return value
	}
	return applyDigits(value, synth.Card(rng))
}

// synthINN builds a 12-digit INN with valid control sums.
func synthINN(value string, rng *rand.Rand) string {
	digits := digitsOnly(value)
	if len(digits) != 12 {
		return value
	}
	return applyDigits(value, synth.INN(rng))
}

// synthSNILS builds an 11-digit SNILS with a valid control number.
func synthSNILS(value string, rng *rand.Rand) string {
	digits := digitsOnly(value)
	if len(digits) != 11 {
		return value
	}
	return applyDigits(value, synth.SNILS(rng))
}

// synthPassport builds a 4+6 digit passport with series 4[0-9]{3}.
func synthPassport(value string, rng *rand.Rand) string {
	digits := digitsOnly(value)
	if len(digits) != 10 {
		return value
	}
	return applyDigits(value, synth.Passport(rng))
}

// monthWords are the genitive month names used to detect word-form dates.
var monthWords = []string{
	monthJanuary, monthFebruary, monthMarch, monthApril, monthMay, monthJune,
	monthJuly, monthAugust, monthSeptember, monthOctober, monthNovember, monthDecember,
}

// isWordDate reports whether value is a date written in words (contains a
// genitive month name).
func isWordDate(value string) bool {
	lower := strings.ToLower(value)
	for _, m := range monthWords {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// synthDate builds a random valid date in 1950-2005 in the same format.
func synthDate(value string, rng *rand.Rand) string {
	if isWordDate(value) {
		return synthDateWord(value, rng)
	}
	return synthDateNumeric(value, rng)
}

// synthDateWord builds a word-form date "<day> <month genitive> <year>
// [года|г.]", preserving the tail of the source.
func synthDateWord(value string, rng *rand.Rand) string {
	year := 1950 + rng.Intn(56)
	month := 1 + rng.Intn(12)
	day := 1 + rng.Intn(daysInMonth(year, month))
	tail := dateTailGoda
	if strings.HasSuffix(strings.ToLower(value), dateTailG) {
		tail = dateTailG
	}
	return itoa(day) + " " + monthWords[month-1] + " " + itoa(year) + " " + tail
}

// synthDateNumeric builds a numeric date in the same format and with the same
// separators as the source. Supported formats: dd.mm.yyyy, dd/mm/yyyy,
// dd-mm-yyyy, yyyy-mm-dd, yyyy.mm.dd and dd.mm.yy.
func synthDateNumeric(value string, rng *rand.Rand) string {
	sep := byte(0)
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			sep = value[i]
			break
		}
	}
	if sep == 0 {
		return value
	}
	digits := digitsOnly(value)
	year := 1950 + rng.Intn(56)
	month := 1 + rng.Intn(12)
	day := 1 + rng.Intn(daysInMonth(year, month))
	dd := twoDigits(day)
	mm := twoDigits(month)
	yy := itoa(year)
	switch len(digits) {
	case 6:
		return dd + string(sep) + mm + string(sep) + itoa(year%100)
	case 8:
		if strings.IndexByte(value, sep) == 4 {
			return yy + string(sep) + mm + string(sep) + dd
		}
		return dd + string(sep) + mm + string(sep) + yy
	default:
		return value
	}
}

// daysInMonth returns the number of days in the given month of the given year.
func daysInMonth(year, month int) int {
	dm := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && isLeapYear(year) {
		return 29
	}
	return dm[month-1]
}

// isLeapYear reports whether y is a leap year.
func isLeapYear(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}

// twoDigits formats n as a zero-padded two-digit string.
func twoDigits(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

// synthEmail builds user<hash6>@example.com.
func synthEmail(value string, rng *rand.Rand) string {
	return synth.HashEmail(value)
}

// applyDigits replaces the digits of value with the digits of fake, preserving
// all non-digit characters and their positions.
func applyDigits(value, fake string) string {
	var b strings.Builder
	fi := 0
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			if fi < len(fake) {
				b.WriteByte(fake[fi])
				fi++
			} else {
				b.WriteByte(value[i])
			}
		} else {
			b.WriteByte(value[i])
		}
	}
	return b.String()
}

func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hex6 returns the low 24 bits of h as six hex digits.
func hex6(h uint64) string {
	const hexdigits = "0123456789abcdef"
	var b [6]byte
	for i := 0; i < 6; i++ {
		b[i] = hexdigits[h&0xf]
		h >>= 4
	}
	return string(b[:])
}
