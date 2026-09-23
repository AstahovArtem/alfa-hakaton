package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

// This file collects end-to-end regressions (through the default pipeline,
// like the accuracy/pipeline tests in regex_test.go) for a round of
// production leaks found in review. Each TestReview* documents the leak it
// closes; nearby negative cases guard against the fix over-triggering.

// --- B2: bare 10-digit mobile number after a phone label -------------------

func TestReviewPhoneBareMobileWithContext(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"telephoneLabel", "Телефон 9161234567", "9161234567"},
		{"telAbbrev", "тел. 9161234567", "9161234567"},
		{"mobAbbrev", "моб 9031234567", "9031234567"},
		{"mobileWord", "мобильный номер 9161234567", "9161234567"},
		{"dashedWithContext", "мобильный 916-123-45-67", "916-123-45-67"},
		{"whatsapp", "whatsapp 9161234567", "9161234567"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatPhone, c.in, c.want)
		})
	}
}

func TestReviewPhoneBareMobileNoContext(t *testing.T) {
	// Without a phone label a bare 10-digit number must not be treated as a
	// phone: it is ambiguous with account numbers and order numbers.
	cases := []string{
		"9161234567",
		"Номер заказа 9161234567",
		"счёт 40817810099910004312",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatPhone) {
			t.Errorf("no phone expected for %q, got %+v", c, res.Spans)
		}
	}
}

func TestReviewPhoneSpacedWithLeadingDigit(t *testing.T) {
	// The existing 7/8-prefixed rule already covers spaced groups; keep it
	// working alongside the new bare-mobile rule.
	res := runPipeline(t, "Перезвоните на 8 916 123 45 67")
	assertSpanValue(t, res, pii.CatPhone, "Перезвоните на 8 916 123 45 67", "8 916 123 45 67")
}

func TestReviewTollFreeHotlineUnchanged(t *testing.T) {
	// Bank hotline numbers stay non-personal; do not change this behaviour.
	res := runPipeline(t, "Горячая линия 8 800 100-00-00, звоните бесплатно")
	if hasCategory(t, res, pii.CatPhone) {
		t.Errorf("toll-free hotline should not be a personal phone, got %+v", res.Spans)
	}
}

// --- B4: bank domain email, service mailbox vs personal mailbox ------------

func TestReviewPersonalEmailOnBankDomain(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"dotted", "ivan.petrov@alfabank.ru", "ivan.petrov@alfabank.ru"},
		{"initial", "i.ivanov@alfabank.ru", "i.ivanov@alfabank.ru"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatEmail, c.in, c.want)
		})
	}
}

func TestReviewServiceMailboxOnBankDomainNotPII(t *testing.T) {
	cases := []string{
		"info@alfabank.ru",
		"support@alfabank.ru",
		"press@alfabank.ru",
		"pr@alfabank.ru",
		"hr@alfabank.ru",
		"noreply@alfabank.ru",
		"no-reply@alfabank.ru",
		"help@alfabank.ru",
		"feedback@alfabank.ru",
		"mail@alfabank.ru",
		"office@alfabank.ru",
		"clients@alfabank.ru",
		"client@alfabank.ru",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatEmail) {
			t.Errorf("service mailbox %q should not be detected, got %+v", c, res.Spans)
		}
	}
}

func TestReviewServiceLocalPartOnOtherDomainIsPII(t *testing.T) {
	// The service-mailbox exclusion only applies to the org's own domain: a
	// generic-looking local part on an unrelated domain is still a personal
	// address as far as this rule is concerned.
	res := runPipeline(t, "info@example.com")
	if !hasCategory(t, res, pii.CatEmail) {
		t.Errorf("info@example.com should be detected outside the bank domain, got %+v", res.Spans)
	}
}

// --- B5: PIN/CVV deny-context only blocks when it is the direct label ------

func TestReviewPinCvvDenyWordAfterValueStillMasked(t *testing.T) {
	cases := []struct {
		name string
		in   string
		cat  pii.Category
		want string
	}{
		{"pinCardThenPassword", "ПИН карты 4321, пароль не помню", pii.CatPIN, "4321"},
		{"cvvThenIntercom", "CVV 123, код от домофона не помню", pii.CatCVV, "123"},
		{"pinThenSafe", "PIN 1234, пароль от сейфа другой", pii.CatPIN, "1234"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, c.cat, c.in, c.want)
		})
	}
}

func TestReviewPinCvvDenyWordAsDirectLabelStillBlocked(t *testing.T) {
	cases := []string{
		"код от домофона 1234",
		"пароль 1234",
		"пин-код от домофона 4321",
		"Пароль от Wi-Fi 1234, пин-код от домофона 4321",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatPIN) || hasCategory(t, res, pii.CatCVV) {
			t.Errorf("no pin/cvv expected for %q, got %+v", c, res.Spans)
		}
	}
}

// --- B7: division code with space and en-dash separators -------------------

func TestReviewDivisionCodeSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"space", "код подразделения 770 001", "770 001"},
		{"spacedDash", "код подразделения 770 - 001", "770 - 001"},
		{"enDash", "код подразделения 770–001", "770–001"},
		{"dash", "код подразделения 770-001", "770-001"},
		{"bareDigits", "код подразделения 770001", "770001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatDivisionCode, c.in, c.want)
		})
	}
}

func TestReviewDivisionCodeNoContext(t *testing.T) {
	cases := []string{"770 001", "770 - 001", "770–001"}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatDivisionCode) {
			t.Errorf("no division code expected without context for %q, got %+v", c, res.Spans)
		}
	}
}

// --- B8: driver license, spaced region+series, Latin look-alikes -----------

func TestReviewDriverLicenseSeriesForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cyrillicSpaced", "ВУ 77 АА 123456", "77 АА 123456"},
		{"cyrillicLongLabel", "водительское удостоверение 77 АА 123456", "77 АА 123456"},
		{"digitsOneGap", "в/у 7712 345678", "7712 345678"},
		{"cyrillicNoSpace", "ВУ 77АА123456", "77АА123456"},
		{"latinAA", "ВУ 77AA123456", "77AA123456"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatDriverLicense, c.in, c.want)
		})
	}
}

func TestReviewDriverLicenseNoContext(t *testing.T) {
	res := runPipeline(t, "77 АА 123456")
	if hasCategory(t, res, pii.CatDriverLicense) {
		t.Errorf("no driver license expected without context, got %+v", res.Spans)
	}
}

// --- B13: spaced/dashed INN with invalid checksum still masked -------------

func TestReviewINNSpacedInvalidChecksum(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"spaced", "ИНН 5001 0073 2258", "5001 0073 2258"},
		{"dashed", "ИНН 5001-0073-2258", "5001-0073-2258"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatINN, c.in, c.want)
		})
	}
}

func TestReviewINNOrgContextStillExcluded(t *testing.T) {
	// Existing decision, must stay green: a labeled 10-digit INN in an
	// organisation context is not personal data.
	cases := []string{
		"ИНН организации 7707083893",
		"Организация: ИНН 7707083893, КПП 770701001",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatINN) {
			t.Errorf("org INN should not be detected for %q, got %+v", c, res.Spans)
		}
	}
}

// --- B14a: NBSP / narrow NBSP separators in card, phone, passport ----------

func TestReviewNBSPSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		cat  pii.Category
	}{
		{"cardNBSP", "Номер карты 4111 1111 1111 1111", pii.CatCardNumber},
		{"cardNarrowNBSP", "Номер карты 4111 1111 1111 1111", pii.CatCardNumber},
		{"phoneNBSP", "Тел. 8 916 123 45 67", pii.CatPhone},
		{"passportNBSP", "паспорт 4509 123456", pii.CatPassport},
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

// --- B14c: match_lower fallback stays case-insensitive when Lower is not
// byte-length compatible with Raw (e.g. the text also contains a Kelvin sign,
// U+212A, which lowercases to a shorter byte sequence).

func TestReviewMatchLowerFallbackCaseInsensitive(t *testing.T) {
	// The Kelvin sign forces Text.LowerOK() to false for the whole text (its
	// lowercase form "k" has a different UTF-8 byte length), which used to
	// make match_lower rules fall back to a case-sensitive regexp and lose
	// uppercase Cyrillic dates and passport numbers.
	kelvin := "K"
	in := kelvin + " ДАТА РОЖДЕНИЯ 5 МАРТА 1985"
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatBirthDate) {
		t.Errorf("expected birth_date in %q despite the Kelvin sign, got %+v", in, res.Spans)
	}

	inPassport := kelvin + " ПАСПОРТ 4509 123456"
	res = runPipeline(t, inPassport)
	if !hasCategory(t, res, pii.CatPassport) {
		t.Errorf("expected passport in %q despite the Kelvin sign, got %+v", inPassport, res.Spans)
	}
}

// --- B17: CVV2/CVC and Russian PIN label variants ---------------------------

func TestReviewCVVPINLabelVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		cat  pii.Category
		want string
	}{
		{"cvv2", "CVV2: 186", pii.CatCVV, "186"},
		{"cvc", "cvc 456", pii.CatCVV, "456"},
		{"pinDash", "ПИН-код 1234", pii.CatPIN, "1234"},
		{"pinSpace", "пин код 1234", pii.CatPIN, "1234"},
		{"pinColon", "ПИН: 1234", pii.CatPIN, "1234"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, c.cat, c.in, c.want)
		})
	}
}
