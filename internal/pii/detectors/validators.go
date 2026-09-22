package detectors

import (
	"regexp"
	"strconv"
	"strings"
)

// Validators maps a validator name to its function. Each validator normalizes
// the input (removes spaces, dashes, parentheses) before checking.
var Validators = map[string]func(match string) bool{
	"luhn":              luhn,
	"inn":               inn,
	"snils":             snils,
	"passport":          passport,
	"phone":             phone,
	"phone10":           phone10,
	"phone_e164":        phoneE164,
	"date":              date,
	"date_short_year":   dateShortYear,
	"not_service_email": notServiceEmail,
	"not_toll_free":     notTollFree,
}

var nonDigit = regexp.MustCompile(`[^\d]`)

// tollFreePrefix is the Russian toll-free 8 800 prefix. Numbers starting with
// it are corporate contacts rather than personal data.
const tollFreePrefix = "800"

var wordDateRe = regexp.MustCompile(`^(\d{1,2})(?:-го|-е|-ого|-его)?\s+([а-яё]+)\s+(\d{4})(?:\s+(?:г\.|года|г))?$`)

// yearFirstDateRe matches "1985 г., 5 марта" (year first, then day + month).
var yearFirstDateRe = regexp.MustCompile(`^(\d{4})\s+г\.?\s*,?\s+(\d{1,2})(?:-го|-е|-ого|-его)?\s+([а-яё]+)$`)

// serviceEmailLocalParts are local parts of corporate/service mailboxes that
// are not personal data.
var serviceEmailLocalParts = map[string]bool{
	"support": true, "info": true, "noreply": true, "no-reply": true,
	"help": true, "sales": true, "office": true, "hello": true,
}

// notServiceEmail rejects an email whose local part is a corporate service
// mailbox (support, info, noreply, ...).
func notServiceEmail(match string) bool {
	at := strings.Index(match, "@")
	if at < 0 {
		return true
	}
	local := strings.ToLower(match[:at])
	return !serviceEmailLocalParts[local]
}

// notTollFree rejects a Russian toll-free 8 800 number, which is a corporate
// contact rather than personal data.
func notTollFree(match string) bool {
	d := digits(match)
	if len(d) == 11 && d[0] == '8' && d[1:4] == tollFreePrefix {
		return false
	}
	return true
}

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
// It rejects toll-free 8 800 numbers, which are corporate contacts rather than
// personal data.
func phone(match string) bool {
	d := digits(match)
	if len(d) != 11 {
		return false
	}
	if d[0] == '8' && d[1:4] == tollFreePrefix {
		return false
	}
	return d[0] == '7' || d[0] == '8'
}

// phone10 validates a 10-digit Russian phone number written with a parenthesised
// area code and no leading 8/+7 (e.g. "(495) 123-45-67"). It rejects toll-free
// 800 numbers.
func phone10(match string) bool {
	d := digits(match)
	if len(d) != 10 {
		return false
	}
	return d[:3] != tollFreePrefix
}

// phoneE164 validates an E.164 phone number: a leading '+' followed by 10-15
// digits (country code + national number), with optional separators.
func phoneE164(match string) bool {
	d := digits(match)
	return len(d) >= 10 && len(d) <= 15
}

var monthNames = map[string]int{
	"января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
	"июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
	// Abbreviated month forms (with or without a trailing dot).
	"янв": 1, "янв.": 1, "фев": 2, "фев.": 2, "мар": 3, "мар.": 3, "апр": 4, "апр.": 4,
	"май": 5, "май.": 5, "июн": 6, "июн.": 6, "июл": 7, "июл.": 7,
	"авг": 8, "авг.": 8, "сен": 9, "сен.": 9, "сент": 9, "сент.": 9, "окт": 10, "окт.": 10,
	"ноя": 11, "ноя.": 11, "дек": 12, "дек.": 12,
}

// date validates a date. It accepts numeric dates in several orders and
// word-form dates (day + month in genitive). For ambiguous numeric formats it
// accepts if at least one interpretation is valid.
func date(match string) bool {
	s := strings.TrimSpace(match)
	lower := strings.ToLower(s)

	// Word form: "12 мая 1990" or "12 мая 1990 г." / "12 мая 1990 года",
	// "5-го марта 1985", "05 мар 1985".
	if m := wordDateRe.FindStringSubmatch(lower); m != nil {
		return wordDate(m)
	}

	// Year-first word form: "1985 г., 5 марта".
	if m := yearFirstDateRe.FindStringSubmatch(lower); m != nil {
		return yearFirstDate(m)
	}

	// Numeric form: split on separators.
	a, b, c, ok := numericParts(s)
	if !ok {
		return false
	}
	// Try all interpretations where one part is a plausible year (1900-2100).
	return validYMD(a, b, c) || validYMD(c, a, b) || validYMD(c, b, a) || validYMD(a, c, b)
}

// numericParts splits a numeric date on separators and parses the three parts.
func numericParts(s string) (a, b, c int, ok bool) {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '/' || r == '-'
	})
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	a, err1 := strconv.Atoi(parts[0])
	b, err2 := strconv.Atoi(parts[1])
	c, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, false
	}
	return a, b, c, true
}

// wordDate validates a "day month year" word-form date match.
func wordDate(m []string) bool {
	day, _ := strconv.Atoi(m[1])
	month, ok := monthNames[strings.TrimSuffix(m[2], ".")]
	if !ok {
		return false
	}
	year, _ := strconv.Atoi(m[3])
	return validYMD(year, month, day)
}

// yearFirstDate validates a "year, day month" word-form date match.
func yearFirstDate(m []string) bool {
	year, _ := strconv.Atoi(m[1])
	day, _ := strconv.Atoi(m[2])
	month, ok := monthNames[strings.TrimSuffix(m[3], ".")]
	if !ok {
		return false
	}
	return validYMD(year, month, day)
}

// dateShortYear validates a numeric date with a two-digit year (e.g. 05.03.85).
// The two-digit year is interpreted as 19xx or 20xx.
func dateShortYear(match string) bool {
	s := strings.TrimSpace(match)
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
	// One part must be a plausible two-digit year (00-99).
	return shortYearAsLast(a, b, c) || shortYearAsFirst(a, b, c)
}

// shortYearAsLast interprets c as a two-digit year and checks the remaining
// day/month orderings.
func shortYearAsLast(a, b, c int) bool {
	if c < 0 || c > 99 {
		return false
	}
	year := 1900 + c
	return validYMD(year, a, b) || validYMD(year, b, a)
}

// shortYearAsFirst interprets a as a two-digit year and checks the remaining
// day/month ordering.
func shortYearAsFirst(a, b, c int) bool {
	if a < 0 || a > 99 {
		return false
	}
	year := 1900 + a
	return validYMD(year, b, c)
}

func validYMD(year, month, day int) bool {
	if !inRange(year, 1900, 2100) || !inRange(month, 1, 12) || day < 1 {
		return false
	}
	daysInMonth := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if isLeap(year) && month == 2 {
		daysInMonth[1] = 29
	}
	return day <= daysInMonth[month-1]
}

func inRange(v, lo, hi int) bool {
	return v >= lo && v <= hi
}

func isLeap(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}
