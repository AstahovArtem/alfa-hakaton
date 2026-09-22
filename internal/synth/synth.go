// Package synth generates plausible fake PII values with valid control sums.
// It is shared by the masking synthetic strategy and the blind dataset
// generator so both produce the same value formats.
package synth

import (
	"embed"
	"hash/fnv"
	"math/rand"
	"strings"
	"sync"
	"unicode/utf8"
)

//go:embed dict/*.txt
var dictFS embed.FS

// Dict holds the loaded name dictionaries.
type Dict struct {
	names    []string
	surnames []string
	patrM    []string
	patrF    []string
}

var (
	dictOnce sync.Once
	dictData *Dict
)

// LoadDict loads the name dictionaries once.
func LoadDict() *Dict {
	dictOnce.Do(func() {
		dictData = &Dict{
			names:    readDict("dict/first_names.txt"),
			surnames: readDict("dict/surnames.txt"),
			patrM: []string{"Александрович", "Андреевич", "Борисович", "Васильевич", "Викторович",
				"Владимирович", "Дмитриевич", "Евгеньевич", "Иванович", "Игоревич", "Константинович",
				"Михайлович", "Николаевич", "Олегович", "Павлович", "Петрович", "Сергеевич", "Фёдорович", "Юрьевич"},
			patrF: []string{"Александровна", "Андреевна", "Борисовна", "Васильевна", "Викторовна",
				"Владимировна", "Дмитриевна", "Евгеньевна", "Ивановна", "Игоревна", "Константиновна",
				"Михайловна", "Николаевна", "Олеговна", "Павловна", "Петровна", "Сергеевна", "Фёдоровна", "Юрьевна"},
		}
	})
	return dictData
}

func readDict(path string) []string {
	data, err := dictFS.ReadFile(path)
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

// Phone returns an 11-digit Russian phone number starting with 7.
func Phone(rng *rand.Rand) string {
	return "7" + "9" + randDigits(rng, 9)
}

// Card returns a 16-digit card number with a valid Luhn check digit.
func Card(rng *rand.Rand) string {
	bin := "4"
	if rng.Intn(2) == 0 {
		bin = "5"
	}
	bin += randDigits(rng, 2)
	body := bin + randDigits(rng, 12)
	return body + string(luhnCheckDigit(body))
}

// INN returns a 12-digit individual INN with valid control sums.
func INN(rng *rand.Rand) string {
	base := randDigits(rng, 10)
	n11 := innControl(base, []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8})
	n12 := innControl(base+string(n11), []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8})
	return base + string(n11) + string(n12)
}

// INN10 returns a 10-digit legal-entity INN with a valid control digit.
func INN10(rng *rand.Rand) string {
	base := randDigits(rng, 9)
	n10 := innControl(base, []int{2, 4, 10, 3, 5, 9, 4, 6, 8})
	return base + string(n10)
}

func innControl(d string, weights []int) byte {
	sum := 0
	for i, w := range weights {
		sum += int(d[i]-'0') * w
	}
	return byte('0' + sum%11%10)
}

// SNILS returns an 11-digit SNILS with a valid control number.
func SNILS(rng *rand.Rand) string {
	base := randDigits(rng, 9)
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(base[i]-'0') * (9 - i)
	}
	var control int
	if sum < 100 {
		control = sum
	} else if sum == 100 || sum == 101 {
		control = 0
	} else {
		control = sum % 101
		if control == 100 {
			control = 0
		}
	}
	return base + twoDigits(control)
}

// Passport returns a 10-digit Russian passport series+number.
func Passport(rng *rand.Rand) string {
	return "4" + randDigits(rng, 3) + randDigits(rng, 6)
}

// ForeignPassport returns a 9-digit foreign passport number.
func ForeignPassport(rng *rand.Rand) string {
	return "7" + randDigits(rng, 1) + randDigits(rng, 7)
}

// DriverLicense returns a 10-digit driver license number.
func DriverLicense(rng *rand.Rand) string {
	return twoDigits(1+rng.Intn(90)) + twoDigits(1+rng.Intn(90)) + randDigits(rng, 6)
}

// DivisionCode returns a 6-digit division code in the form 3-3.
func DivisionCode(rng *rand.Rand) string {
	return randDigits(rng, 3) + "-" + randDigits(rng, 3)
}

// CVV returns a 3-digit card security code.
func CVV(rng *rand.Rand) string {
	return randDigits(rng, 3)
}

// PIN returns a 4-digit PIN.
func PIN(rng *rand.Rand) string {
	return randDigits(rng, 4)
}

// Date returns a valid date in 1950-2005 as day.month.year.
func Date(rng *rand.Rand) string {
	year := 1950 + rng.Intn(56)
	month := 1 + rng.Intn(12)
	day := 1 + rng.Intn(daysInMonth(year, month))
	return twoDigits(day) + "." + twoDigits(month) + itoa(year)
}

// DateWord returns a valid date in words: "12 мая 1990 года".
func DateWord(rng *rand.Rand) string {
	year := 1950 + rng.Intn(56)
	month := 1 + rng.Intn(12)
	day := 1 + rng.Intn(daysInMonth(year, month))
	return itoa(day) + " " + monthGenitive(month) + " " + itoa(year) + " года"
}

// Email returns a plausible email address.
func Email(rng *rand.Rand) string {
	user := randDigits(rng, 6)
	domains := []string{"mail.ru", "yandex.ru", "gmail.com", "example.com", "bank.ru"}
	return "user" + user + "@" + domains[rng.Intn(len(domains))]
}

// FullName returns a random full name (surname + first + patronymic).
func FullName(rng *rand.Rand) string {
	d := LoadDict()
	first := d.names[rng.Intn(len(d.names))]
	surname := d.surnames[rng.Intn(len(d.surnames))]
	patr := d.patrM[rng.Intn(len(d.patrM))]
	if isFemaleName(first) {
		surname = feminize(surname)
		patr = d.patrF[rng.Intn(len(d.patrF))]
	}
	return capitalize(surname) + " " + capitalize(first) + " " + patr
}

// FullNameGenitive returns a full name in the genitive case (for "заявление от").
func FullNameGenitive(rng *rand.Rand) string {
	d := LoadDict()
	first := d.names[rng.Intn(len(d.names))]
	surname := d.surnames[rng.Intn(len(d.surnames))]
	patr := d.patrM[rng.Intn(len(d.patrM))]
	female := isFemaleName(first)
	if female {
		surname = feminize(surname)
		patr = d.patrF[rng.Intn(len(d.patrF))]
	}
	return genitiveSurname(capitalize(surname), female) + " " + genitiveName(capitalize(first), female) + " " + genitivePatr(patr)
}

// isFemaleName guesses gender from the first name ending.
func isFemaleName(name string) bool {
	lower := strings.ToLower(name)
	for _, suf := range []string{"а", "я", "ия", "ья"} {
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
			return s[:len(s)-len(suf)] + "а"
		}
	}
	return s
}

// genitiveSurname returns the genitive form of a surname.
func genitiveSurname(s string, female bool) string {
	lower := strings.ToLower(s)
	if female {
		for _, suf := range []string{"ова", "ева", "ёва", "ина", "ына"} {
			if strings.HasSuffix(lower, suf) {
				return s[:len(s)-1] + "ой"
			}
		}
		return s
	}
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(lower, suf) {
			return s + "а"
		}
	}
	return s
}

// genitiveName returns the genitive form of a first name.
func genitiveName(s string, female bool) string {
	lower := strings.ToLower(s)
	if female {
		for _, suf := range []string{"ия", "ья"} {
			if strings.HasSuffix(lower, suf) {
				return s[:len(s)-1] + "и"
			}
		}
		for _, suf := range []string{"а", "я"} {
			if strings.HasSuffix(lower, suf) {
				return s[:len(s)-1] + "ы"
			}
		}
		return s
	}
	for _, suf := range []string{"ий", "ей"} {
		if strings.HasSuffix(lower, suf) {
			return s[:len(s)-2] + "я"
		}
	}
	for _, suf := range []string{"й"} {
		if strings.HasSuffix(lower, suf) {
			return s[:len(s)-1] + "я"
		}
	}
	return s
}

// genitivePatr returns the genitive form of a patronymic.
func genitivePatr(p string) string {
	lower := strings.ToLower(p)
	for _, suf := range []string{"овна", "евна", "ична", "инична"} {
		if strings.HasSuffix(lower, suf) {
			return p + "ы"
		}
	}
	for _, suf := range []string{"ович", "евич", "ич"} {
		if strings.HasSuffix(lower, suf) {
			return p + "а"
		}
	}
	return p
}

// capitalize uppercases the first rune of s.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	first, size := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(first)) + s[size:]
}

func daysInMonth(year, month int) int {
	dm := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && isLeapYear(year) {
		return 29
	}
	return dm[month-1]
}

func isLeapYear(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}

var monthGenitiveList = []string{"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря"}

func monthGenitive(m int) string {
	if m < 1 || m > 12 {
		return ""
	}
	return monthGenitiveList[m-1]
}

// luhnCheckDigit returns the check digit that makes d+check pass Luhn.
func luhnCheckDigit(d string) byte {
	sum := 0
	double := true
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return byte('0' + (10-sum%10)%10)
}

// HashEmail builds a deterministic email from a value (used by the synthetic
// masking strategy).
func HashEmail(value string) string {
	h := fnv.New64a()
	h.Write([]byte(value))
	hash := h.Sum64()
	const hexdigits = "0123456789abcdef"
	var b [6]byte
	for i := 0; i < 6; i++ {
		b[i] = hexdigits[hash&0xf]
		hash >>= 4
	}
	return "user" + string(b[:]) + "@example.com"
}

func randDigits(rng *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + rng.Intn(10)))
	}
	return b.String()
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
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
