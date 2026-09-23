package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

// This file collects end-to-end regressions for production leaks/misfires
// reported for the address, birth_place, citizenship and passport_issuer
// detectors. Each case runs through the default pipeline, like the other
// pipeline-level tests in this package.

// B1: an unlabelled country name outside the old, narrow dictionary (e.g.
// "Франция") leaked unmasked. The dictionary now covers the UN member states,
// their common inflected forms, and a label-anchored fallback for anything
// still missing (including adjective forms).
func TestReviewCitizenshipCountryCoverage(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"franceLabel", "Гражданство: Франция", "Франция"},
		{"franceGenitiveCitizen", "гражданин Франции", "Франции"},
		{"uzbekGenitiveCitizen", "гражданка Узбекистана", "Узбекистана"},
		{"italy", "гражданство Италии", "Италии"},
		{"spain", "гражданство Испании", "Испании"},
		{"labelAdjective", "гражданство: французское", "французское"},
		{"labelDash", "гражданство - Франция", "Франция"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			assertSpanValue(t, res, pii.CatCitizenship, c.in, c.want)
		})
	}
}

// B1 traps: a bare label with no value, and an unlabelled mention of a
// country used in a non-citizenship sense (e.g. a location or a business
// origin), must not be flagged.
func TestReviewCitizenshipTraps(t *testing.T) {
	cases := []string{
		"гражданство: не указано",
		"Кем выдан: Консульством Российской Федерации в Париже",
		"компания из Франции",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatCitizenship) {
			t.Errorf("citizenship should not detect %q, got %+v", c, res.Spans)
		}
	}
}

// B3: an organisation-address exception word mentioned earlier in the same
// sentence (but a different clause) must not suppress a personal address that
// a later personal marker ("живу", "проживаю", ...) introduces.
func TestReviewAddressExceptionBoundToClause(t *testing.T) {
	in := "Сообщил банку: работаю в офисе, живу по адресу ул. Ленина, д. 5."
	assertSpanValue(t, runPipeline(t, in), pii.CatAddress, in, "ул. Ленина, д. 5")
}

// B3 traps: the existing organisation-address exceptions (bank branch, ATM,
// office as the direct head of the address) must still be suppressed.
func TestReviewAddressExceptionStillTraps(t *testing.T) {
	cases := []string{
		"отделение банка по адресу ул. Тверская, 1",
		"офис на ул. Тверская 1",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatAddress) {
			t.Errorf("address should not detect org address %q, got %+v", c, res.Spans)
		}
	}
}

// B11: labelled address components must accept "=" and "-"/"—" as separators,
// in addition to ":", including compact key=value forms.
func TestReviewAddressLabelSeparators(t *testing.T) {
	in := "Страна = Россия; Город = Москва; Улица = Пречистенка; Дом = 17"
	res := runPipeline(t, in)
	want := []string{"Россия", "Москва", "Пречистенка", "17"}
	var got []string
	for _, s := range res.Spans {
		if s.Category == pii.CatAddress {
			got = append(got, in[s.Start:s.End])
		}
	}
	if len(got) != len(want) {
		t.Fatalf("address spans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address span %d = %q, want %q", i, got[i], want[i])
		}
	}

	in2 := "city=Москва, street=Пречистенка"
	res2 := runPipeline(t, in2)
	if !hasCategory(t, res2, pii.CatAddress) {
		t.Errorf("no address span for %q", in2)
	}
}

// B11 trap: a hyphenated compound word (not a label-value pair) must not be
// mistaken for a "-"-separated labelled component.
func TestReviewAddressLabelSeparatorTrap(t *testing.T) {
	in := "Экскурсия для сотрудников: музей-квартира Пушкина на Мойке, 12, затем дом-музей Достоевского."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatAddress) {
		t.Errorf("address should not detect %q, got %+v", in, res.Spans)
	}
}

// B15: a single labelled address component must go through the
// organisation-exception check, even when the organisation header sits in the
// previous sentence.
func TestReviewAddressLabeledOrgException(t *testing.T) {
	in := "Адрес отделения банка. Город: Москва"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatAddress) {
		t.Errorf("address should not detect org header field %q, got %+v", in, res.Spans)
	}
}

// B12: after a birth marker and a settlement-type word, a lowercase place name
// (not in the city dictionary) is captured too.
func TestReviewBirthplaceLowercaseSettlement(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"родился в деревне малые вяземы", "малые вяземы"},
		{"место рождения: село большие кайбицы", "село большие кайбицы"},
		{"родилась в пос. Шушенское", "пос. Шушенское"},
		{"уроженец г. Тихорецк", "г. Тихорецк"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatBirthPlace, c.in, c.want)
	}
}

// B12 trap: the famous-person exception still holds for a well-known subject.
func TestReviewBirthplaceFamousTrap(t *testing.T) {
	in := "Поэт Александр Сергеевич Пушкин родился в Москве"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should not detect famous person %q, got %+v", in, res.Spans)
	}
}

// B12 trap: a bare year after "родился в" is not a place.
func TestReviewBirthplaceYearTrap(t *testing.T) {
	in := "родился в 1985 году"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should not detect a year %q, got %+v", in, res.Spans)
	}
}

// B10: the issuing-authority start words must cover consulates/embassies, and
// the span must stop at a sensible boundary rather than swallowing nothing
// past the authority name.
func TestReviewIssuerConsulate(t *testing.T) {
	in := "Кем выдан: Консульством Российской Федерации в Париже"
	assertSpanValue(t, runPipeline(t, in), pii.CatPassportIssuer, in, "Консульством Российской Федерации в Париже")
}

// B10: the issuer span must not swallow a following date or division code.
func TestReviewIssuerStopsBeforeDateAndCode(t *testing.T) {
	in := "Паспорт выдан Консульством России во Франции 12.05.2010, код подразделения 770-001."
	assertSpanValue(t, runPipeline(t, in), pii.CatPassportIssuer, in, "Консульством России во Франции")
}
