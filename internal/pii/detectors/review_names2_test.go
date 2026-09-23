package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

// Regressions from the second person-name recall pass (dialogue/form layouts,
// short reply names, declined names next to a suffix-guessed given name).
// Every case runs through the default pipeline, the same way a request
// reaches /process, not just the names detector in isolation.

// A labeled form field is its own name span: each of "Фамилия", "Имя" and
// "Отчество" is masked independently, matching how the split-layout datasets
// annotate it, and it works regardless of the value's case.
func TestReviewLabeledFieldIsOwnSpan(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"surnameColon", "1. Фамилия: Воронцова", "Воронцова"},
		{"givenNameColonNextLine", "2. Имя: Екатерина\n3. Отчество: Дмитриевна", "Екатерина"},
		{"patronymicColonNextLine", "2. Имя: Екатерина\n3. Отчество: Дмитриевна", "Дмитриевна"},
		{"surnameUppercase", "фамилия: ПОПОВА; имя: Ульяна; отчество: сергеевна", "ПОПОВА"},
		{"patronymicLowercase", "фамилия: ПОПОВА; имя: Ульяна; отчество: сергеевна", "сергеевна"},
		{"surnameNoColon", "снилс: 145 680 392 80, фамилия: рахимов", "рахимов"},
		{"witnessSurname", "Свидетель Козлова показала, что видела кражу", "Козлова"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertHasSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
		})
	}
}

// assertHasSpanValue checks that some span of category cat in res covers
// exactly the substring want of in, unlike assertSpanValue which only checks
// the first span of that category.
func assertHasSpanValue(t *testing.T, res pii.Result, cat pii.Category, in, want string) {
	t.Helper()
	for _, s := range res.Spans {
		if s.Category == cat && in[s.Start:s.End] == want {
			return
		}
	}
	t.Errorf("no %s span %q in %q, got %+v", cat, want, in, res.Spans)
}

// A multi-line labeled form does not bridge a field label into the gap-name
// matcher: the label word between "Екатерина" and "Дмитриевна" must not be
// mistaken for the unknown given name that normally sits between a surname
// and a patronymic.
func TestReviewLabeledFieldNoCrossLineMerge(t *testing.T) {
	in := "2. Имя: Екатерина\n3. Отчество: Дмитриевна"
	res := runPipeline(t, in)
	for _, s := range res.Spans {
		if s.Category != pii.CatFullName {
			continue
		}
		got := in[s.Start:s.End]
		if got != "Екатерина" && got != "Дмитриевна" {
			t.Errorf("unexpected full_name span %q in %q, want only the labeled words on their own", got, in)
		}
	}
}

// A field-label separator (a colon before an unrelated trailing word) must
// not be swallowed into the gap-name span either, even when the trailing word
// happens to be misclassified as a patronymic by a coincidental suffix match.
func TestReviewGapNameStopsAtLabelSeparator(t *testing.T) {
	in := "Контакты созаемщика Юсупова Рустама: основной +7 (917) 400-11-22"
	res := runPipeline(t, in)
	assertSpanValue(t, res, pii.CatFullName, in, "Юсупова Рустама")
	for _, s := range res.Spans {
		if s.Category == pii.CatFullName && in[s.Start:s.End] != "Юсупова Рустама" {
			t.Errorf("gap name must not extend past the label separator: got %q in %q", in[s.Start:s.End], in)
		}
	}
}

// A maiden surname in parentheses must still extend the span even though the
// gap-name matcher now restricts what may sit between the surname and the
// patronymic (whitespace and parentheses only).
func TestReviewMaidenSurnameStillExtends(t *testing.T) {
	in := "Сафина (Ганиева) Гульнара Ильдаровна"
	assertSpanValue(t, runPipeline(t, in), pii.CatFullName, in, in)
}

// A hyphenated compound or foreign surname directly before a confirmed
// given-name+patronymic pair extends the span backward, even when the
// surname itself does not match any dictionary or suffix pattern.
func TestReviewHyphenatedSurnameExtendsSpan(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"nominative", "Со стороны подрядчика подписант — Кравец-Задорожная Оксана Витальевна.", "Кравец-Задорожная Оксана Витальевна"},
		{"declinedInstrumental", "Карта оформлена на Волкову-Брандт Александру Евгеньевну.", "Волкову-Брандт Александру Евгеньевну"},
		{"foreignSurname", "Мюллер-Шмидт Анна Карловна (Anna Müller-Schmidt), гражданство ФРГ.", "Мюллер-Шмидт Анна Карловна"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
		})
	}
}

// A Turkic patronymic marker ("кызы"/"оглы"/"улы") is included in the span
// even when it follows a surname+initials triple rather than the
// surname+name+name form turkicPatronymic normally expects.
func TestReviewTurkicMarkerAfterInitials(t *testing.T) {
	in := "Собственник квартиры — Ахмедова С. Ф. кызы, доверенное лицо — Т. А. Гарибян."
	assertSpanValue(t, runPipeline(t, in), pii.CatFullName, in, "Ахмедова С. Ф. кызы")
}

// A polite-address greeting licenses an unknown given name (not in the
// dictionary) followed by a patronymic, without needing a surname.
func TestReviewGreetingNamePatr(t *testing.T) {
	in := "Уважаемая Севиль Эльдаровна! Напоминаем о платеже по кредиту."
	assertSpanValue(t, runPipeline(t, in), pii.CatFullName, in, "Севиль Эльдаровна")
}

// A declined surname+given-name+patronymic sequence is matched in full even
// when the given name itself is coincidentally suffix-guessed as a surname
// (many feminine and Turkic given names share surname-like endings): the
// middle token's own guessed role must not block it from being recognised as
// the given name that bridges a confirmed surname to a confirmed patronymic.
func TestReviewMiddleNameSuffixGuessedAsSurname(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"declinedInstrumental", "клиент связался Григорьевым Павлом Станиславовичем, уточнил cvv-код", "Григорьевым Павлом Станиславовичем"},
		{"nominative", "Я, Мамедов Эльчин Гусейнович, 07.06.1981 г.р., проживающий по адресу", "Мамедов Эльчин Гусейнович"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
		})
	}
}

// A famous person's full name stays masked when a birth date spelled out in
// words (not just a numeric date) confirms the name is the client's own, not
// a historical reference.
func TestReviewFamousNameWithWordedBirthDate(t *testing.T) {
	in := "Я, Пушкин Александр Сергеевич, 1999 года рождения, подтверждаю согласие на обработку данных."
	if !hasCategory(t, runPipeline(t, in), pii.CatFullName) {
		t.Errorf("famous name with a worded birth date nearby should be PII: %q", in)
	}
}

// False-positive traps: an ordinary Russian word that happens to end in the
// same letters as a declined patronymic or surname suffix must not be
// mistaken for a name, even next to role-marker context. Each case names the
// one word that must never appear as a full_name span; a genuine name
// elsewhere in the same text (e.g. "Юсупова Рустама") is still allowed.
func TestReviewSuffixCollisionTrapsStayUnmasked(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		trapped string
	}{
		{
			"adjectiveCollidesWithPatronymicSuffix",
			"Контакты созаемщика Юсупова Рустама: основной +7 (917) 400-11-22",
			"основной",
		},
		{
			"inflectedGrazhdaninCollidesWithSurnameSuffix",
			"паспорт иностранного гражданина 71 1234567",
			"гражданина",
		},
		{
			"relationalAdjectiveNearClientContext",
			"клиент прислал ссылку из фишингового письма, в ней видна карта",
			"фишингового",
		},
		{
			"shortAdjectiveNearImyaContext",
			"Карта на имя ZULFIYA AKHMEDOVA готова, заберите в отделении",
			"готова",
		},
		{
			"famousSurnameAsStreetNameNearClientContext",
			"клиент спросил, есть ли отделение на улице чехова",
			"чехова",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			for _, s := range res.Spans {
				if s.Category == pii.CatFullName && c.in[s.Start:s.End] == c.trapped {
					t.Errorf("%q should not be a full_name span in %q", c.trapped, c.in)
				}
			}
		})
	}
}
