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
	out := s.synthFor(value, cat, rng, doc)
	if doc != nil {
		doc.Remember(value, out)
	}
	return out
}

// synthFor dispatches to the synthetic generator for cat.
func (s *syntheticStrategy) synthFor(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	switch cat {
	case pii.CatFullName:
		return s.synthName(value, cat, rng, doc)
	case pii.CatPhone:
		return synthPhone(value, cat, rng, doc)
	case pii.CatCardNumber:
		return synthCard(value, cat, rng, doc)
	case pii.CatINN:
		return synthINN(value, cat, rng, doc)
	case pii.CatSNILS:
		return synthSNILS(value, cat, rng, doc)
	case pii.CatPassport:
		return synthPassport(value, cat, rng, doc)
	case pii.CatDate, pii.CatBirthDate, pii.CatPassportDate:
		return synthDate(value, cat, rng, doc)
	case pii.CatEmail:
		return synthEmail(value, rng)
	default:
		return tokenFallback(value, cat, doc)
	}
}

// newSeeded returns a deterministic RNG seeded from category+value. The
// 64-bit FNV sum is folded into the int64 range by clearing the sign bit
// rather than clamping to math.MaxInt64, so the full range of hash values
// maps to distinct seeds instead of half of them collapsing onto one seed.
func newSeeded(cat pii.Category, value string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(string(cat)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	sum := h.Sum64()
	seed := int64(sum &^ (1 << 63))
	// #nosec G404 -- deterministic fake values seeded by input, not security
	return rand.New(rand.NewSource(seed))
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
// gender inferred from the patronymic/surname ending. It falls back to a
// [CATEGORY_N] token when there is nothing to preserve the shape of, or the
// name dictionaries failed to load.
func (s *syntheticStrategy) synthName(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	words := strings.Fields(value)
	if len(words) == 0 || len(s.names) == 0 || len(s.surnames) == 0 || len(s.patrM) == 0 || len(s.patrF) == 0 {
		return tokenFallback(value, cat, doc)
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

// synthPhone replaces the digits after "+7 9" keeping the original
// separators. Numbers that do not have the expected 11 digits (e.g. a foreign
// number) fall back to a token rather than leaking the original.
func synthPhone(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	digits := digitsOnly(value)
	if len(digits) != 11 {
		return tokenFallback(value, cat, doc)
	}
	return applyDigits(value, synth.Phone(rng))
}

// synthCard builds a 16-digit card with a valid Luhn and a 4xxx/5xxx BIN,
// keeping the original separators.
func synthCard(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	digits := digitsOnly(value)
	if len(digits) < 13 || len(digits) > 19 {
		return tokenFallback(value, cat, doc)
	}
	return applyDigits(value, synth.Card(rng))
}

// synthINN builds a 12-digit INN with valid control sums. A 10-digit
// (organization) INN or any other length falls back to a token.
func synthINN(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	digits := digitsOnly(value)
	if len(digits) != 12 {
		return tokenFallback(value, cat, doc)
	}
	return applyDigits(value, synth.INN(rng))
}

// synthSNILS builds an 11-digit SNILS with a valid control number.
func synthSNILS(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	digits := digitsOnly(value)
	if len(digits) != 11 {
		return tokenFallback(value, cat, doc)
	}
	return applyDigits(value, synth.SNILS(rng))
}

// synthPassport builds a 4+6 digit passport with series 4[0-9]{3}.
func synthPassport(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	digits := digitsOnly(value)
	if len(digits) != 10 {
		return tokenFallback(value, cat, doc)
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
func synthDate(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	if isWordDate(value) {
		return synthDateWord(value, rng)
	}
	return synthDateNumeric(value, cat, rng, doc)
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
// dd-mm-yyyy, yyyy-mm-dd, yyyy.mm.dd and dd.mm.yy. Anything else (no
// separator found, or an unsupported digit count) falls back to a token.
func synthDateNumeric(value string, cat pii.Category, rng *rand.Rand, doc *DocState) string {
	sep := byte(0)
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			sep = value[i]
			break
		}
	}
	if sep == 0 {
		return tokenFallback(value, cat, doc)
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
		return tokenFallback(value, cat, doc)
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
