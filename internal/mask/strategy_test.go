package mask

import (
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
