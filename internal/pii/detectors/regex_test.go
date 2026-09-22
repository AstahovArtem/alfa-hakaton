package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func runPipeline(t *testing.T, text string) pii.Result {
	t.Helper()
	p := pii.NewPipeline(Default()...)
	return p.Run(text)
}

func hasCategory(t *testing.T, res pii.Result, cat pii.Category) bool {
	t.Helper()
	for _, s := range res.Spans {
		if s.Category == cat {
			return true
		}
	}
	return false
}

func TestPhoneDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "Перезвоните по номеру +7 (916) 123-45-67", true},
		{"positive8", "Мой номер 89161234567", true},
		{"negative10digits", "Номер заказа 9161234567", false},
		{"negativeForeign", "Позвоните на +1 916 123 45 67", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPhone); got != c.want {
				t.Errorf("phone detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestEmailDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "Напишите на IVAN.Petrov@Example.com", true},
		{"positive2", "почта user_name+tag@mail.ru", true},
		{"negative", "это не email @example", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatEmail); got != c.want {
				t.Errorf("email detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestEmailCyrillic(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cyrillicLocal", "лебедева30@gmail.com", "лебедева30@gmail.com"},
		{"mixedLocal", "фeдоров92@gmail.com", "фeдоров92@gmail.com"},
		{"cyrillicDomain", "иван@почта.рф", "иван@почта.рф"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			found := false
			for _, s := range res.Spans {
				if s.Category == pii.CatEmail {
					found = true
					if got := c.in[s.Start:s.End]; got != c.want {
						t.Errorf("email value for %q = %q, want %q", c.in, got, c.want)
					}
				}
			}
			if !found {
				t.Errorf("no email span for %q", c.in)
			}
		})
	}
}

func TestINNDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "Мой ИНН 500100732259", true},
		{"positiveLegal", "ИНН организации 3664069397", true},
		{"negative", "Номер 500100732258", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatINN); got != c.want {
				t.Errorf("inn detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestCardNumberDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "Номер карты 4111 1111 1111 1111", true},
		{"positiveContiguous", "карта 4111111111111111", true},
		{"negative", "4111 1111 1111 1112", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatCardNumber); got != c.want {
				t.Errorf("card detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestCVVDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "CVV код 123", true},
		{"positiveCvc", "cvc 456", true},
		{"negativeNoContext", "123", false},
		{"negativeNoContext2", "код 123", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatCVV); got != c.want {
				t.Errorf("cvv detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestPINDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "ПИН-код 1234", true},
		{"positivePin", "pin 5678", true},
		{"negativeNoContext", "1234", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPIN); got != c.want {
				t.Errorf("pin detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestPassportDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "паспорт 4509 123456", true},
		{"positiveContiguous", "паспорт 4509123456", true},
		{"positiveSeries", "серия 4509 номер 123456", true},
		{"negative", "паспорт 0000 123456", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPassport); got != c.want {
				t.Errorf("passport detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDivisionCodeDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "код подразделения 770-001", true},
		{"positiveShort", "к/п 770-001", true},
		{"negativeNoContext", "770-001", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatDivisionCode); got != c.want {
				t.Errorf("division detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDriverLicenseDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "водительское удостоверение 77 12 345678", true},
		{"positiveAA", "права 77АА 123456", true},
		{"negativeNoContext", "77 12 345678", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatDriverLicense); got != c.want {
				t.Errorf("driver detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestSNILSDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "СНИЛС 112-233-445 95", true},
		{"positiveContiguous", "снилс 11223344595", true},
		{"negativeNoContext", "112-233-445 95", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatSNILS); got != c.want {
				t.Errorf("snils detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestForeignPassportDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "загранпаспорт 71 1234567", true},
		{"positiveZagran", "загран 71 1234567", true},
		{"negativeNoContext", "71 1234567", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatForeignPassport); got != c.want {
				t.Errorf("foreign detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDateDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "дата 12.05.1990", true},
		{"positiveWord", "12 мая 1990 года", true},
		{"positiveISO", "1990-05-12", true},
		{"negativeYearOnly", "родился в 1799 году", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatDate); got != c.want {
				t.Errorf("date detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestBirthDateReclassify(t *testing.T) {
	res := runPipeline(t, "дата рождения 12.05.1990")
	if !hasCategory(t, res, pii.CatBirthDate) {
		t.Errorf("expected birth_date, got %+v", res.Spans)
	}
}

func TestPassportDateReclassify(t *testing.T) {
	res := runPipeline(t, "паспорт выдан 12.05.1990")
	if !hasCategory(t, res, pii.CatPassportDate) {
		t.Errorf("expected passport_date, got %+v", res.Spans)
	}
}

func TestPassportDateReclassifyLongIssuer(t *testing.T) {
	res := runPipeline(t, "Паспорт 4509 123456 выдан ОУФМС России по г. Москве по району Хамовники 12.05.2010, код подразделения 770-001")
	if !hasCategory(t, res, pii.CatPassportDate) {
		t.Errorf("expected passport_date for date after long issuer, got %+v", res.Spans)
	}
	if hasCategory(t, res, pii.CatDate) {
		t.Errorf("date should be reclassified to passport_date, got %+v", res.Spans)
	}
}

func TestPassportDateReclassifyRightContext(t *testing.T) {
	res := runPipeline(t, "паспорт 4509 123456 выдан 12.05.2010, код подразделения 770-001")
	if !hasCategory(t, res, pii.CatPassportDate) {
		t.Errorf("expected passport_date via right context 'код подразделения', got %+v", res.Spans)
	}
}

func TestBirthDateReclassifyRightContext(t *testing.T) {
	res := runPipeline(t, "родился 12.05.1990, место рождения: г. Москва")
	if !hasCategory(t, res, pii.CatBirthDate) {
		t.Errorf("expected birth_date via right context 'место рождения', got %+v", res.Spans)
	}
}

func TestBirthDateReclassifyRightContextGR(t *testing.T) {
	cases := []string{
		"16 июня 1980 года г.р.",
		"22.08.1990 года рождения",
		"16 июня 1980 года г. р.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if !hasCategory(t, res, pii.CatBirthDate) {
			t.Errorf("expected birth_date for %q, got %+v", c, res.Spans)
		}
	}
}

func TestPassportDateAfterLongIssuer(t *testing.T) {
	res := runPipeline(t, "выдан ТП №5 ОУФМС России по Республике Татарстан в г. Казани 18 августа 2019 года")
	if !hasCategory(t, res, pii.CatPassportDate) {
		t.Errorf("expected passport_date for date after long issuer, got %+v", res.Spans)
	}
	if hasCategory(t, res, pii.CatDate) {
		t.Errorf("date should be reclassified to passport_date, got %+v", res.Spans)
	}
}

func TestForeignPassportContexts(t *testing.T) {
	cases := []string{
		"иностранный паспорт 61 4074552",
		"паспорт иностранного гражданина 71 1234567",
		"заграничный паспорт 71 1234567",
		"загран. 71 1234567",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if !hasCategory(t, res, pii.CatForeignPassport) {
			t.Errorf("expected foreign_passport for %q, got %+v", c, res.Spans)
		}
	}
}

func TestPassportSeriesTwoPairs(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"серия 45 75 № 841641", "45 75 № 841641"},
		{"45 75 № 841641", "45 75 № 841641"},
		{"серия: 45 75, номер: 841641", "45 75, номер: 841641"},
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatPassport {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("passport value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no passport span for %q", c.in)
		}
	}
}

func TestCardNumberNoTrailingSpace(t *testing.T) {
	in := "карта 5536470369258147 "
	res := runPipeline(t, in)
	for _, s := range res.Spans {
		if s.Category == pii.CatCardNumber {
			if got := in[s.Start:s.End]; got != "5536470369258147" {
				t.Errorf("card span should not include trailing space, got %q", got)
			}
		}
	}
}

func TestCitizenshipDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "гражданство РФ", true},
		{"positiveFull", "гражданство: Российская Федерация", true},
		{"positiveCitizen", "гражданин России", true},
		{"positiveKazakh", "гражданство Республики Казахстан", true},
		{"negative", "гражданство", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatCitizenship); got != c.want {
				t.Errorf("citizenship detect %q = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestCitizenshipSpanExcludesContext(t *testing.T) {
	res := runPipeline(t, "гражданство РФ")
	for _, s := range res.Spans {
		if s.Category == pii.CatCitizenship {
			if s.Start != 23 {
				t.Errorf("citizenship span should start after context word, got start=%d", s.Start)
			}
		}
	}
}

func TestPhoneNotInsideLongNumber(t *testing.T) {
	res := runPipeline(t, "счёт 40817810099910004312")
	if len(res.Spans) != 0 {
		t.Errorf("account number should produce no spans, got %+v", res.Spans)
	}
}

func TestCVVNotCapturingNeighbor(t *testing.T) {
	res := runPipeline(t, "Код безопасности карты 123, 4321 это пин-код")
	for _, s := range res.Spans {
		if s.Start == 48 && s.End == 52 {
			if s.Category != pii.CatPIN {
				t.Errorf("4321 should be pin, got %s", s.Category)
			}
		}
	}
	if !hasCategory(t, res, pii.CatPIN) {
		t.Errorf("4321 should be pin, got %+v", res.Spans)
	}
}

func TestCVVNotInDigitSequence(t *testing.T) {
	res := runPipeline(t, "карта 5536 9138 1234 5678 cvv 123")
	if len(res.Spans) != 1 || res.Spans[0].Category != pii.CatCVV {
		t.Errorf("expected exactly one cvv span for 123, got %+v", res.Spans)
	}
	if got := res.Spans[0].Start; got != 35 {
		t.Errorf("only the real cvv 123 should be detected, got span at %d", got)
	}
}

func TestCVVPINCloserKeywordWins(t *testing.T) {
	res := runPipeline(t, "пин 1234 и cvv")
	if !hasCategory(t, res, pii.CatPIN) {
		t.Errorf("closer keyword pin should win over cvv, got %+v", res.Spans)
	}
	if hasCategory(t, res, pii.CatCVV) {
		t.Errorf("cvv should not win when pin keyword is closer, got %+v", res.Spans)
	}
}

func TestDateYearDayMonth(t *testing.T) {
	res := runPipeline(t, "2020.15.03")
	if !hasCategory(t, res, pii.CatDate) {
		t.Errorf("2020.15.03 should be a date (Y-D-M), got %+v", res.Spans)
	}
}

func TestPINRejectNonCard(t *testing.T) {
	in := "Пароль от Wi-Fi 1234, пин-код от домофона 4321"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatPIN) {
		t.Errorf("pin should not detect non-card codes %q, got %+v", in, res.Spans)
	}
}

func TestCVVBackOfCard(t *testing.T) {
	in := "код с обратной стороны карты 321"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatCVV {
			found = true
			if got := in[s.Start:s.End]; got != "321" {
				t.Errorf("cvv value = %q, want %q", got, "321")
			}
		}
	}
	if !found {
		t.Errorf("no cvv span for %q", in)
	}
}

func TestINNOrgNotPII(t *testing.T) {
	in := "Организация: ИНН 7707083893, КПП 770701001, ОГРН 1027700132195"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatINN) {
		t.Errorf("org INN should not be detected %q, got %+v", in, res.Spans)
	}
}

func TestEmailServiceNotPII(t *testing.T) {
	in := "Support: support@alfabank.ru работает круглосуточно"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatEmail) {
		t.Errorf("service email should not be detected %q, got %+v", in, res.Spans)
	}
}

func TestTollFreePhoneNotPII(t *testing.T) {
	in := "Горячая линия банка 8 800 200-00-00, бесплатно по России"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatPhone) {
		t.Errorf("toll-free phone should not be detected %q, got %+v", in, res.Spans)
	}
}
