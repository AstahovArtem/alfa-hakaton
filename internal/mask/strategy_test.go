package mask

import (
	"strings"
	"testing"

	"pdn-shield/internal/pii"
)

func TestTokenStrategy(t *testing.T) {
	s := NewToken()
	doc := NewDocState()
	cases := []struct {
		cat   pii.Category
		value string
		want  string
	}{
		{pii.CatFullName, "Иванов Иван Иванович", "[FULL_NAME_1]"},
		{pii.CatPhone, "+7 (916) 123-45-67", "[PHONE_1]"},
		{pii.CatPhone, "89161234567", "[PHONE_2]"},
		{pii.CatCardNumber, "4111 1111 1111 1111", "[CARD_NUMBER_1]"},
	}
	for _, tc := range cases {
		got := s.Mask(tc.value, tc.cat, doc)
		if got != tc.want {
			t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
		}
	}
}

func TestTokenSameValueSameReplacement(t *testing.T) {
	s := NewToken()
	doc := NewDocState()
	a := s.Mask("4111 1111 1111 1111", pii.CatCardNumber, doc)
	b := s.Mask("4111 1111 1111 1111", pii.CatCardNumber, doc)
	if a != b {
		t.Errorf("same value got different tokens: %q vs %q", a, b)
	}
}

func TestSyntheticDeterministic(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	a := s.Mask("Иванов Иван Иванович", pii.CatFullName, doc)
	b := s.Mask("Иванов Иван Иванович", pii.CatFullName, doc)
	if a != b {
		t.Errorf("synthetic not deterministic: %q vs %q", a, b)
	}
}

func TestSyntheticValidators(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	card := s.Mask("4111 1111 1111 1111", pii.CatCardNumber, doc)
	if !luhnValid(card) {
		t.Errorf("synthetic card %q fails Luhn", card)
	}
	inn := s.Mask("500100732259", pii.CatINN, doc)
	if !innValid(inn) {
		t.Errorf("synthetic INN %q invalid", inn)
	}
	snils := s.Mask("112-233-445 95", pii.CatSNILS, doc)
	if !snilsValid(snils) {
		t.Errorf("synthetic SNILS %q invalid", snils)
	}
}

func TestSyntheticPhoneFormat(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	got := s.Mask("+7 (916) 123-45-67", pii.CatPhone, doc)
	if len(digitsOnly(got)) != 11 {
		t.Errorf("synthetic phone %q does not have 11 digits", got)
	}
	if got[0] != '+' || got[1] != '7' {
		t.Errorf("synthetic phone %q lost +7 prefix", got)
	}
}

func TestSyntheticEmail(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	got := s.Mask("ivan@mail.ru", pii.CatEmail, doc)
	if got != "user"+hex6(fnvHash("ivan@mail.ru"))+"@example.com" {
		t.Errorf("synthetic email %q unexpected", got)
	}
}

func TestSyntheticFallbackToken(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	got := s.Mask("г. Москва", pii.CatBirthPlace, doc)
	if got != "[BIRTH_PLACE_1]" {
		t.Errorf("synthetic fallback = %q, want [BIRTH_PLACE_1]", got)
	}
}

func TestSyntheticDate(t *testing.T) {
	s := NewSynthetic()
	doc := NewDocState()
	for _, value := range []string{
		"12 мая 1990 года",
		"1 января 2000 года",
		"31 декабря 1985 года",
		"15 сентября 2005 года",
	} {
		checkWordDate(t, s, doc, value)
	}
	for _, value := range []string{
		"12.05.1990",
		"01.01.2000",
		"31.12.1985",
		"15.09.2005",
	} {
		checkNumericDate(t, s, doc, value)
	}
}

// checkWordDate verifies a word-form date masks to a month word and a 4-digit
// year.
func checkWordDate(t *testing.T, s Strategy, doc *DocState, value string) {
	t.Helper()
	got := s.Mask(value, pii.CatBirthDate, doc)
	if !isWordDate(got) {
		t.Errorf("word date %q -> %q: missing month word", value, got)
	}
	words := strings.Fields(got)
	if len(words) != 4 || words[3] != "года" {
		t.Errorf("word date %q -> %q: want 4 words ending in года", value, got)
	}
	if len(words[2]) != 4 {
		t.Errorf("word date %q -> %q: year %q not 4 digits", value, got, words[2])
	}
}

// checkNumericDate verifies a numeric date masks to exactly 8 digits with no
// month word.
func checkNumericDate(t *testing.T, s Strategy, doc *DocState, value string) {
	t.Helper()
	got := s.Mask(value, pii.CatBirthDate, doc)
	if isWordDate(got) {
		t.Errorf("numeric date %q -> %q: unexpected month word", value, got)
	}
	if len(digitsOnly(got)) != 8 {
		t.Errorf("numeric date %q -> %q: want 8 digits", value, got)
	}
}
