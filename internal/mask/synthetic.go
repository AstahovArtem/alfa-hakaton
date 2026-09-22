package mask

import (
	"embed"
	"hash/fnv"
	"math/rand"
	"strings"
	"sync"
	"unicode/utf8"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/synth"
)

//go:embed dict/*.txt
var synthFS embed.FS

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

func (s *syntheticStrategy) Name() string { return "synthetic" }

func (s *syntheticStrategy) load() {
	s.loadOnce.Do(func() {
		s.names = readSynthDict("dict/first_names.txt")
		s.surnames = readSynthDict("dict/surnames.txt")
		s.patrM = []string{"Александрович", "Андреевич", "Борисович", "Васильевич", "Викторович",
			"Владимирович", "Дмитриевич", "Евгеньевич", "Иванович", "Игоревич", "Константинович",
			"Михайлович", "Николаевич", "Олегович", "Павлович", "Петрович", "Сергеевич", "Фёдорович", "Юрьевич"}
		s.patrF = []string{"Александровна", "Андреевна", "Борисовна", "Васильевна", "Викторовна",
			"Владимировна", "Дмитриевна", "Евгеньевна", "Ивановна", "Игоревна", "Константиновна",
			"Михайловна", "Николаевна", "Олеговна", "Павловна", "Петровна", "Сергеевна", "Фёдоровна", "Юрьевна"}
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
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
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

// synthDate builds a random valid date in 1950-2005 in the same format.
func synthDate(value string, rng *rand.Rand) string {
	// Word form: "12 мая 1990 года".
	if strings.ContainsAny(value, "аяеёиюя") && !strings.ContainsAny(value, "0123456789./-") {
		words := strings.Fields(value)
		if len(words) >= 3 {
			return synth.DateWord(rng) + " " + trailingWord(value)
		}
	}
	// Numeric form: replace digits keeping separators.
	return applyDigits(value, synth.Date(rng))
}

func trailingWord(value string) string {
	words := strings.Fields(value)
	if len(words) == 0 {
		return ""
	}
	last := words[len(words)-1]
	if strings.ContainsAny(last, "0123456789") {
		return ""
	}
	return last
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
