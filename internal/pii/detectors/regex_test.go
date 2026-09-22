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

// assertSpanValue checks that the first span of category cat in res covers the
// substring want of in.
func assertSpanValue(t *testing.T, res pii.Result, cat pii.Category, in, want string) {
	t.Helper()
	for _, s := range res.Spans {
		if s.Category != cat {
			continue
		}
		if got := in[s.Start:s.End]; got != want {
			t.Errorf("%s value for %q = %q, want %q", cat, in, got, want)
		}
		return
	}
	t.Errorf("no %s span for %q", cat, in)
}

// assertSpanConfidence checks that the first span of category cat in res has
// confidence want.
func assertSpanConfidence(t *testing.T, res pii.Result, cat pii.Category, in string, want float64) {
	t.Helper()
	for _, s := range res.Spans {
		if s.Category != cat {
			continue
		}
		if s.Confidence != want {
			t.Errorf("confidence for %q = %v, want %v", in, s.Confidence, want)
		}
		return
	}
	t.Errorf("no %s span for %q", cat, in)
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
		{"positiveForeign", "Позвоните на +1 916 123 45 67", true},
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
			got, found := categoryValue(res, pii.CatEmail, c.in)
			if !found {
				t.Errorf("no email span for %q", c.in)
				return
			}
			if got != c.want {
				t.Errorf("email value for %q = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// categoryValue returns the text of the first span of the given category, or
// ("", false) when none is found.
func categoryValue(res pii.Result, cat pii.Category, text string) (string, bool) {
	for _, s := range res.Spans {
		if s.Category == cat {
			return text[s.Start:s.End], true
		}
	}
	return "", false
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

// Point 9: CVV forms with "на обороте", "код с обратной стороны", "три цифры
// на обороте" and a colon/newline after the label.
func TestCVVBackOfCardForms(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"три цифры на обороте — 921", "921"},
		{"На обороте: 507", "507"},
		{"код с обратной стороны 604", "604"},
		{"CVC: 043", "043"},
		{"код CVV 772", "772"},
		{"CVV2: 186", "186"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatCVV, c.in, c.want)
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

// Point 10: PIN forms with "код от карты" and two candidates after the label.
func TestPINCardCodeForms(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"код от карты — 2580", []string{"2580"}},
		{"пин-код от карты 5536 9104 6872 0190 это 4071 или 4017", []string{"4071", "4017"}},
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		for _, want := range c.want {
			assertPinValue(t, res, c.in, want)
		}
	}
}

// assertPinValue checks that res contains a pin span equal to want.
func assertPinValue(t *testing.T, res pii.Result, in, want string) {
	t.Helper()
	for _, s := range res.Spans {
		if s.Category == pii.CatPIN && in[s.Start:s.End] == want {
			return
		}
	}
	t.Errorf("no pin span %q in %q, got %+v", want, in, res.Spans)
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
	res := runPipeline(
		t,
		"Паспорт 4509 123456 выдан ОУФМС России по г. Москве по району Хамовники 12.05.2010, код подразделения 770-001",
	)
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
		assertSpanValue(t, runPipeline(t, c.in), pii.CatPassport, c.in, c.want)
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
	in := "карта 5536 9138 1234 5678 cvv 123"
	res := runPipeline(t, in)
	var cvvSpans []pii.Span
	for _, s := range res.Spans {
		if s.Category == pii.CatCVV {
			cvvSpans = append(cvvSpans, s)
		}
	}
	if len(cvvSpans) != 1 {
		t.Errorf("expected exactly one cvv span for 123, got %+v", res.Spans)
		return
	}
	if got := in[cvvSpans[0].Start:cvvSpans[0].End]; got != "123" {
		t.Errorf("only the real cvv 123 should be detected, got %q", got)
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

func TestSoftContextInvalidChecksum(t *testing.T) {
	cases := []struct {
		name string
		in   string
		cat  pii.Category
	}{
		{"inn", "ИНН 770123456789", pii.CatINN},
		{"snils", "СНИЛС 123-456-789 01", pii.CatSNILS},
		{"snilsPhrase", "страховой номер 123-456-789 01", pii.CatSNILS},
		{"card", "карта 4276 1234 5678 9012", pii.CatCardNumber},
		{"cardPlural", "карты 4276 1234 5678 9012", pii.CatCardNumber},
		{"cardPan", "pan 4276 1234 5678 9012", pii.CatCardNumber},
		{"passport", "паспорт 1234 567890", pii.CatPassport},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if !hasCategory(t, res, c.cat) {
				t.Errorf("expected %s for %q, got %+v", c.cat, c.in, res.Spans)
			}
		})
	}
}

func TestSoftContextConfidenceReduced(t *testing.T) {
	// A soft-passed span (invalid checksum + label) must be 0.2 below the base
	// confidence of a valid match.
	valid := runPipeline(t, "ИНН 500100732259")
	soft := runPipeline(t, "ИНН 770123456789")
	validConf := spanConfidence(valid, pii.CatINN)
	softConf := spanConfidence(soft, pii.CatINN)
	if softConf != validConf-0.2 {
		t.Errorf("soft confidence = %v, want valid %v - 0.2 = %v", softConf, validConf, validConf-0.2)
	}
}

func spanConfidence(res pii.Result, cat pii.Category) float64 {
	for _, s := range res.Spans {
		if s.Category == cat {
			return s.Confidence
		}
	}
	return 0
}

func TestSoftContextTraps(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"orderNumber", "Заказ 1234567890"},
		{"accountNumber", "счёт 40817810099910004312"},
		{"innNoLabel", "номер 500100732258"},
		{"cardNoLabel", "4111 1111 1111 1112"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if len(res.Spans) != 0 {
				t.Errorf("expected no spans for %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

func TestPassportForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"seriesNoSpace", "Паспорт РФ 0304 № 771562", "0304 № 771562"},
		{"seriesNoSpaceAfterNo", "клиент показал 4509 №123465", "4509 №123465"},
		{"seriesAbbrev", "паспорт: с. 4509 н. 123456", "4509 н. 123456"},
		{"seriesWord", "9203 номер 604718", "9203 номер 604718"},
		{"seriesColon", "Паспорт: 2404 № 318077", "2404 № 318077"},
		{"seriesAbbrevPassport", "паспорт с. 4619 н. 004821", "4619 н. 004821"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatPassport, c.in, c.want)
		})
	}
}

func TestDivisionCodeBare(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "код подразделения 770001", true},
		{"positiveKod", "выдан, код 372-002", true},
		{"negativeNoContext", "770001", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatDivisionCode); got != c.want {
				t.Errorf("division bare detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestDivisionCodeBareNotPassportNumber(t *testing.T) {
	// The 6-digit passport number "887120" must not be detected as a division
	// code even though "код подр." appears within the context window.
	res := runPipeline(t, "паспорт 4503 №887120, код подр. 770-071")
	for _, s := range res.Spans {
		if s.Category == pii.CatDivisionCode {
			if got := "паспорт 4503 №887120, код подр. 770-071"[s.Start:s.End]; got == "887120" {
				t.Errorf("passport number 887120 should not be a division_code, got %+v", res.Spans)
			}
		}
	}
}

func TestDriverLicenseTenDigits(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positiveVU", "ВУ 7712345678, категории B, C", true},
		{"positiveSecond", "водительское удостоверение 9921087654", true},
		{"negativeNoContext", "7712345678", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatDriverLicense); got != c.want {
				t.Errorf("driver 10-digit detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestForeignPassportAlphanumeric(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positiveAB", "паспорт иностранного гражданина AB1234567", true},
		{"positiveC", "паспорт иностранного гражданина C03871265", true},
		{"positiveAC", "паспорт иностранного гражданина AC4870162", true},
		{"positiveAR", "паспорт иностранного гражданина AR0391745", true},
		{"positiveE", "паспорт иностранного гражданина E58329104", true},
		{"positiveDigits", "паспорт иностранного гражданина 533418206", true},
		{"negativeNoContext", "AB1234567", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatForeignPassport); got != c.want {
				t.Errorf("foreign alphanumeric detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestSNILSAlternateSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positiveSpaces", "снилс: 145 680 392 80", true},
		{"positiveDashes", "СНИЛС 201-378-945-49", true},
		{"negativeNoContext", "145 680 392 80", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatSNILS); got != c.want {
				t.Errorf("snils alternate detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestINNSpaced(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "Её ИНН 7729 0061 4723", true},
		{"negativeNoContext", "7729 0061 4723", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatINN); got != c.want {
				t.Errorf("inn spaced detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestPhoneFourDigitCode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positiveParen", "8 (4872) 36-01-22", true},
		{"positiveSpace", "рабочий 8 4872 11-22-33", true},
		{"positivePlus7", "Телефон: +7 (4932) 41-18-09", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPhone); got != c.want {
				t.Errorf("phone 4-digit code detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestPhoneMoscowNoPrefix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positive", "по номеру (495) 123-45-67", true},
		{"negativeNoContext", "(495) 123-45-67", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPhone); got != c.want {
				t.Errorf("phone moscow detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestPhoneE164(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"positiveUzbek", "телефон +998 90 123 45 67", true},
		{"positiveChina", "телефон +86 138 1234 5678", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPhone); got != c.want {
				t.Errorf("phone e164 detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestTollFreeExcluded(t *testing.T) {
	cases := []string{
		"8-800-200-00-00",
		"8 800 200-00-00",
		"звонить на 8 (800) 555-35-35",
		"Позвоните 8 800 555 35 35",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatPhone) {
			t.Errorf("toll-free should not be detected %q, got %+v", c, res.Spans)
		}
	}
}
