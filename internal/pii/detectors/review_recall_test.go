package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

// This file collects end-to-end regressions (through the default pipeline)
// for a recall pass over the non-name PII categories: birth_place, dates
// (birth_date/date/passport_date), passport, driver_license, snils,
// division_code, phone and passport_issuer. Each TestReview* documents the
// miss it closes; nearby negative cases guard against the fix
// over-triggering.

// --- birth_place: additional context phrases and value shapes --------------

func TestReviewBirthplaceCityRождения(t *testing.T) {
	// "город рождения" is a common synonym of "место рождения", and its
	// value may be a lowercase dictionary city with no settlement prefix.
	in := "дату рождения назвал 3 янв 1979, город рождения омск"
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "омск")
}

func TestReviewBirthplaceUrAbbrev(t *testing.T) {
	in := "01.05.1995 г.р., ур. г. Ош."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "г. Ош")
}

func TestReviewBirthplaceUrNotInsideWord(t *testing.T) {
	// "ур." must be a standalone abbreviation, not part of a longer word.
	in := "структура родилась в бурю"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("no birth_place expected for %q, got %+v", in, res.Spans)
	}
}

func TestReviewBirthplaceBareRepublicTail(t *testing.T) {
	// A Russian republic named without "республика"/"область" (e.g.
	// "Башкирия") stays part of the birth-place value.
	in := "Родился в с. Верхние Киги, Башкирия."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "с. Верхние Киги, Башкирия")
}

func TestReviewBirthplaceRegionKeywordDoesNotEatNextField(t *testing.T) {
	// "область"/"край"/"район"/"асср" only ever follow the region's proper
	// name (unlike "республика"), so they must not swallow an unrelated word
	// starting the next field (e.g. a following "ПАСПОРТ:" label).
	in := "МЕСТО РОЖДЕНИЯ: КОПЕЙСК ЧЕЛЯБИНСКОЙ ОБЛАСТИ\nПАСПОРТ: СЕРИЯ 7505 НОМЕР 318264"
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "КОПЕЙСК ЧЕЛЯБИНСКОЙ ОБЛАСТИ")
}

func TestReviewBirthplaceRepublicDoesNotEatFollowingName(t *testing.T) {
	// The place value caps at two bare words, so a region name followed by an
	// unrelated capitalised word (a person's surname) is not swallowed.
	in := "Уроженка Республики Молдова Чеботарь Виорика Ион, гражданство Румыния."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "Республики Молдова")
}

func TestReviewBirthplaceEnglishBornIn(t *testing.T) {
	in := "she was born in Baku on 14 July 1992 and holds Azerbaijani citizenship."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthPlace, in, "Baku")
}

// --- dates: birth-date reclassification and additional shapes --------------

func TestReviewDateWordsRozhdeniaSuffix(t *testing.T) {
	// A fully worded date followed directly by "рождения" (not just "года
	// рождения", already covered) is a birth date.
	in := "Иванов Иван, пятого марта тысяча девятьсот восемьдесят пятого года рождения, обратился с заявлением."
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatBirthDate) {
		t.Errorf("birth_date expected for %q, got %+v", in, res.Spans)
	}
	if hasCategory(t, res, pii.CatDate) {
		t.Errorf("no bare date expected once reclassified for %q, got %+v", in, res.Spans)
	}
}

func TestReviewBirthYearLabeled(t *testing.T) {
	// A bare year immediately followed by "года рождения" is a birth date,
	// and the label stays inside the span (matching the convention for a
	// full worded date).
	in := "Я, Пушкин Александр Сергеевич, 1999 года рождения, проживающий в Кемерово."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthDate, in, "1999 года рождения")
}

func TestReviewBirthYearWithGRLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"leading", "г.р. 1985", "1985"},
		{"trailing", "1999 г.р.", "1999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatBirthDate, c.in, c.want)
		})
	}
}

func TestReviewBareYearNeverShrinksFullDate(t *testing.T) {
	// The bare-year rule must never win an overlap against a fuller date at
	// the same position (e.g. the "1995" tail of "01.05.1995").
	in := "01.05.1995 г.р."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthDate, in, "01.05.1995")
}

func TestReviewBareYearNoLabelUnmasked(t *testing.T) {
	// Without a birth-year label a bare 4-digit number is too ambiguous to
	// mask (amounts, codes, other IDs).
	in := "Лимит по карте 1985 рублей."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthDate) {
		t.Errorf("no birth_date expected for %q, got %+v", in, res.Spans)
	}
}

func TestReviewDateWordShortYear(t *testing.T) {
	// "25-го марта 90-го": a day and a two-digit year both carrying their own
	// ordinal suffix.
	in := "Родился 25-го марта 90-го."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthDate, in, "25-го марта 90-го")
}

func TestReviewEnglishDate(t *testing.T) {
	in := "The client was born on 14 July 1992."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatBirthDate, in, "14 July 1992")
}

// --- passport / driver_license disambiguation -------------------------------

func TestReviewPassportSeriaNomerAcrossPeriod(t *testing.T) {
	// A period between the labelled series and "номер" (a full sentence
	// break in speech-to-text style dialogue) must not block the match.
	in := "Серия: 40 15. Номер: 998877."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatPassport, in, "40 15. Номер: 998877")
}

func TestReviewDriverLicenseLabeledNumberBeatsPassport(t *testing.T) {
	// "серия XX YY номер NNNNNN" in a driver-license context is a driver
	// license, not a passport, even though the bare shape also matches the
	// passport rule's unlabelled alternative.
	in := "В/у выдано 15 мая 2018, серия 50 33 номер 776655, категории B, B1, M."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatDriverLicense, in, "50 33 номер 776655")
	if hasCategory(t, res, pii.CatPassport) {
		t.Errorf("no passport expected once reclassified for %q, got %+v", in, res.Spans)
	}
}

func TestReviewDriverLicenseLabeledStillNeedsContext(t *testing.T) {
	// The same shape without any driver-license/passport label at all stays
	// unmasked (require_context guards it).
	in := "Комбинация 50 33 номер 776655 ничего не значит."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatDriverLicense) {
		t.Errorf("no driver_license expected for %q, got %+v", in, res.Spans)
	}
}

// --- snils -------------------------------------------------------------------

func TestReviewSnilsStrakhovoyNomer(t *testing.T) {
	// "страховой номер" alone (without the word "снилс") is a valid label.
	in := "Страховой номер 087-654-321 02 принадлежит Иванову Ивану Ивановичу."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatSNILS, in, "087-654-321 02")
}

// --- division_code ------------------------------------------------------------

func TestReviewDivisionCodeRejectsErrorCount(t *testing.T) {
	// The bare "код" context is common in unrelated technical text; an
	// "ошибок"/"ошибка" mention nearby disqualifies the match. "паспорта"
	// (which contains "порт" as a substring) must not be affected by this.
	in := "Сервер вернул код 500-124 ошибок за час, версия сборки 4.5.09, порт 123456."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatDivisionCode) {
		t.Errorf("no division_code expected for %q, got %+v", in, res.Spans)
	}
}

func TestReviewDivisionCodeUnaffectedNearPassport(t *testing.T) {
	in := "В графе «код подразделения» паспорта указан к/п 839-734, сверьте с оригиналом."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatDivisionCode, in, "839-734")
}

// --- phone ---------------------------------------------------------------------

func TestReviewPhoneE164RejectsHotline(t *testing.T) {
	// The e.164 rule must reject a bank's own hotline the same way the
	// Russian-format rule already does, even for an international-format
	// hotline number in the same sentence.
	in := "Горячая линия банка 8 800 200-00-00, бесплатно по России. Для звонков из-за рубежа +7 495 788-88-78."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatPhone) {
		t.Errorf("no phone expected for %q, got %+v", in, res.Spans)
	}
}

// --- passport_issuer -----------------------------------------------------------

func TestReviewIssuerDecadeGap(t *testing.T) {
	// An approximate decade ("в 90-х") between the context verb and the
	// issuing authority must not break the value search.
	in := "паспорт получил в 90-х в отделении милиции Василеостровского района, номер уже недействителен."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatPassportIssuer, in, "отделении милиции Василеостровского района")
}

func TestReviewIssuerVnutrennikhDel(t *testing.T) {
	// "Отделом внутренних дел" (without "МВД"/"ОВД") is recognised as an
	// issuing authority, and the region/city that follows stays part of the
	// value instead of leaking into the address detector.
	in := "выдан Отделом внутренних дел Мотовилихинского района г. Перми 02.10.2006, код подразделения 592-006."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatPassportIssuer, in, "Отделом внутренних дел Мотовилихинского района г. Перми")
	if hasCategory(t, res, pii.CatAddress) {
		t.Errorf("no address expected once the issuer swallows the district for %q, got %+v", in, res.Spans)
	}
}

func TestReviewIssuerGUDoesNotLoseInitialLetter(t *testing.T) {
	// A regression trap: the date-gap tail ("...\s+(?:года|г\.|г)") must not
	// eat the leading "г" of a following "ГУ МВД" (Go's \b never matches
	// around Cyrillic letters, so the trailing alternative needs an explicit
	// boundary instead).
	in := "выдан 30.06.2018 ГУ МВД России по г. Москве."
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatPassportIssuer, in, "ГУ МВД России по г. Москве")
	if !hasCategory(t, res, pii.CatPassportDate) {
		t.Errorf("passport_date expected for %q, got %+v", in, res.Spans)
	}
}

// --- address ---------------------------------------------------------------------

func TestReviewAddressStreetMarkerNotInsideWord(t *testing.T) {
	// The bare "ул" marker has no built-in word boundary in the underlying
	// regex (Go's \b never matches around Cyrillic letters), so it must not
	// start matching inside an unrelated word such as "вернул".
	in := "Сервер вернул код 500-124 ошибок за час, версия сборки 4.5.09, порт 123456."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatAddress) {
		t.Errorf("no address expected for %q, got %+v", in, res.Spans)
	}
}

func TestReviewAddressStreetMarkerStillWorks(t *testing.T) {
	in := "Клиент проживает на ул. Ленина, д. 5."
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatAddress) {
		t.Errorf("address expected for %q, got %+v", in, res.Spans)
	}
}
