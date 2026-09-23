package mask

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestPartialDigits(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	cases := []struct {
		name  string
		cat   pii.Category
		value string
		want  string
	}{
		{"passport", pii.CatPassport, "4509 123456", "45** ****56"},
		{"card_number", pii.CatCardNumber, "4111 1111 1111 1111", "41** **** **** **11"},
		{"phone", pii.CatPhone, "+7 (916) 123-45-67", "+7 (9**) ***-**-67"},
		{"inn", pii.CatINN, "500100732259", "50********59"},
		{"snils", pii.CatSNILS, "112-233-445 95", "11*-***-*** 95"},
		{"division_code", pii.CatDivisionCode, "770-001", "***-***"},
		{"cvv", pii.CatCVV, "123", "***"},
		{"pin", pii.CatPIN, "1234", "****"},
		{"driver_license", pii.CatDriverLicense, "77 12 345678", "77 ** ****78"},
		{"foreign_passport", pii.CatForeignPassport, "71 1234567", "71 *****67"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Mask(tc.value, tc.cat, doc)
			if got != tc.want {
				t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
			}
		})
	}
}

func TestPartialInitials(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	cases := []struct {
		name  string
		cat   pii.Category
		value string
		want  string
	}{
		{"full_name", pii.CatFullName, "Иванов Иван Иванович", "И. И. И."},
		{"card_holder", pii.CatCardHolder, "IVAN IVANOV", "I. I."},
		{"hyphen", pii.CatFullName, "Салтыков-Щедрин", "С.-Щ."},
		{"existing_initial", pii.CatFullName, "Иванов И. О.", "И. И. О."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Mask(tc.value, tc.cat, doc)
			if got != tc.want {
				t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
			}
		})
	}
}

func TestPartialDate(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	cases := []struct {
		name  string
		cat   pii.Category
		value string
		want  string
	}{
		{"numeric", pii.CatBirthDate, "12.05.1990", "**.**.****"},
		{"word", pii.CatBirthDate, "12 мая 1990", "** м** ****"},
		{"word_year", pii.CatPassportDate, "12 мая 1990 года", "** м** **** г***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Mask(tc.value, tc.cat, doc)
			if got != tc.want {
				t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
			}
		})
	}
}

func TestPartialEmail(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	got := s.Mask("ivan.petrov@mail.ru", pii.CatEmail, doc)
	want := "i**********@mail.ru"
	if got != want {
		t.Errorf("Mask(email) = %q, want %q", got, want)
	}
}

func TestPartialWords(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	cases := []struct {
		name  string
		cat   pii.Category
		value string
		want  string
	}{
		{"address", pii.CatAddress, "ул. Ленина, д. 5, кв. 12", "ул. Л*****, д. *, кв. **"},
		{"issuer", pii.CatPassportIssuer, "ГУ МВД России по г. Москве", "Г* М** Р***** п* г. М*****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Mask(tc.value, tc.cat, doc)
			if got != tc.want {
				t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
			}
		})
	}
}

func TestPartialMemo(t *testing.T) {
	s := MustPartial()
	doc := NewDocState()
	a := s.Mask("4111 1111 1111 1111", pii.CatCardNumber, doc)
	b := s.Mask("4111 1111 1111 1111", pii.CatCardNumber, doc)
	if a != b {
		t.Errorf("same value got different replacements: %q vs %q", a, b)
	}
}
