package detectors

import (
	"regexp"
	"strconv"
	"strings"
)

// Validators maps a validator name to its function. Each validator normalizes
// the input (removes spaces, dashes, parentheses) before checking.
var Validators = map[string]func(match string) bool{
	"luhn":     luhn,
	"inn":      inn,
	"snils":    snils,
	"passport": passport,
	"phone":    phone,
	"date":     date,
}

var nonDigit = regexp.MustCompile(`[^\d]`)

var wordDateRe = regexp.MustCompile(`^(\d{1,2})\s+([а-яё]+)\s+(\d{4})(?:\s+(?:г\.|года|г))?$`)

func digits(s string) string {
	return nonDigit.ReplaceAllString(s, "")
}

// luhn validates a card number using the Luhn algorithm.
func luhn(match string) bool {
	d := digits(match)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	double := false
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
	return sum%10 == 0
}

// inn validates a Russian INN (10 digits for legal entities, 12 for individuals).
func inn(match string) bool {
	d := digits(match)
	switch len(d) {
	case 10:
		return inn10(d)
	case 12:
		return inn12(d)
	default:
		return false
	}
}

func inn10(d string) bool {
	weights := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	sum := 0
	for i, w := range weights {
		sum += int(d[i]-'0') * w
	}
	return sum%11%10 == int(d[9]-'0')
}

func inn12(d string) bool {
	w1 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	w2 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s1, s2 := 0, 0
	for i := 0; i < 10; i++ {
		s1 += int(d[i]-'0') * w1[i]
	}
	for i := 0; i < 11; i++ {
		s2 += int(d[i]-'0') * w2[i]
	}
	return s1%11%10 == int(d[10]-'0') && s2%11%10 == int(d[11]-'0')
}

// snils validates a Russian SNILS control number.
func snils(match string) bool {
	d := digits(match)
	if len(d) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
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
	return control == int(d[9]-'0')*10+int(d[10]-'0')
}

// passport validates a Russian passport series (4 digits) and number (6 digits).
func passport(match string) bool {
	d := digits(match)
	if len(d) != 10 {
		return false
	}
	series := d[:4]
	number := d[4:]
	return series != "0000" && number != "000000"
}

// phone validates a Russian phone number: exactly 11 digits, first is 7 or 8.
func phone(match string) bool {
	d := digits(match)
	if len(d) != 11 {
		return false
	}
	return d[0] == '7' || d[0] == '8'
}

var monthNames = map[string]int{
	"января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
	"июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}

// date validates a date. It accepts numeric dates in several orders and
// word-form dates (day + month in genitive). For ambiguous numeric formats it
// accepts if at least one interpretation is valid.
func date(match string) bool {
	s := strings.TrimSpace(match)
	lower := strings.ToLower(s)

	// Word form: "12 мая 1990" or "12 мая 1990 г." / "12 мая 1990 года".
	if m := wordDateRe.FindStringSubmatch(lower); m != nil {
		day, _ := strconv.Atoi(m[1])
		month, ok := monthNames[m[2]]
		if !ok {
			return false
		}
		year, _ := strconv.Atoi(m[3])
		return validYMD(year, month, day)
	}

	// Numeric form: split on separators.
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '/' || r == '-'
	})
	if len(parts) != 3 {
		return false
	}
	a, err1 := strconv.Atoi(parts[0])
	b, err2 := strconv.Atoi(parts[1])
	c, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}

	// Try all interpretations where one part is a plausible year (1900-2100).
	ok := false
	if validYMD(a, b, c) {
		ok = true
	}
	if validYMD(c, a, b) {
		ok = true
	}
	if validYMD(c, b, a) {
		ok = true
	}
	// Y-D-M: year, day, month (e.g. 2020.15.03).
	if validYMD(a, c, b) {
		ok = true
	}
	return ok
}

func validYMD(year, month, day int) bool {
	if year < 1900 || year > 2100 || month < 1 || month > 12 || day < 1 {
		return false
	}
	daysInMonth := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if isLeap(year) && month == 2 {
		daysInMonth[1] = 29
	}
	return day <= daysInMonth[month-1]
}

func isLeap(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}
