package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestFullNameDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"fio", "ИВАНОВ ИВАН ИВАНОВИЧ", true},
		{"fioLower", "иванов иван иванович", true},
		{"fioMixed", "Иванов Иван Иванович", true},
		{"iof", "Иван Иванович Иванов", true},
		{"if", "Иван Петров", true},
		{"fi", "Петров Иван", true},
		{"fInitials", "Иванов И. О.", true},
		{"fInitialsNoSpace", "Иванов И.О.", true},
		{"initialsF", "И. О. Иванов", true},
		{"initialsFNoSpace", "И.О. Иванов", true},
		{"genitive", "паспорт Иванова Ивана Ивановича", true},
		{"genitivePatrFeminine", "Заявление от Петровой Марии Сергеевны", true},
		{"suffixSurnameAfterColon", "Заявитель: Ахметов Руслан Маратович", true},
		{"singleNameContext", "клиент Иван", true},
		{"namePatrContext", "клиент Иван Иванович", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatFullName); got != c.want {
				t.Errorf("full_name detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestFullNameNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"famous", "поэт Александр Пушкин родился в 1799 году"},
		{"famousGenitive", "стихи Александра Пушкина"},
		{"famousFISurnameFirst", "Пушкин Александр"},
		{"capital", "Москва — столица"},
		{"streetSurname", "улица Иванова"},
		{"singleSurname", "Иванов"},
		{"singleSurnameNoContext", "Иванов пришёл"},
		{"suffixOnly", "Петренко Шевчук"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatFullName); got {
				t.Errorf("full_name should not detect %q, got spans: %+v", c.in, res.Spans)
			}
		})
	}
}

func TestFullNameSpanExcludesContext(t *testing.T) {
	res := runPipeline(t, "клиент Иван")
	for _, s := range res.Spans {
		if s.Category == pii.CatFullName {
			if s.Start != 13 {
				t.Errorf("span should start at the name, got start=%d", s.Start)
			}
		}
	}
}

func TestFullNameSpanValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Заявление от Петровой Марии Сергеевны", "Петровой Марии Сергеевны"},
		{"Заявитель: Ахметов Руслан Маратович", "Ахметов Руслан Маратович"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

func TestFullNameConfidence(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"Иванов Иван Иванович", 0.95},
		{"Иван Петров", 0.85},
		{"клиент Иван", 0.8},
	}
	for _, c := range cases {
		assertSpanConfidence(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

func TestFullNameUnknownGivenNameWithPatronymic(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ФИО: Ахметова Айгуль Расуловна", "Ахметова Айгуль Расуловна"},
		{"Оганесян Арам Самвелович", "Оганесян Арам Самвелович"},
		{"Мамедова Севиль Рустамовна", "Мамедова Севиль Рустамовна"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

func TestFullNameFamousWithPatronymic(t *testing.T) {
	cases := []string{
		"Александр Сергеевич Пушкин",
		"Юрий Алексеевич Гагарин",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatFullName) {
			t.Errorf("famous person with patronymic should not be PII: %q, got %+v", c, res.Spans)
		}
	}
}

func TestFullNameSurnameInitialsUppercase(t *testing.T) {
	res := runPipeline(t, "ДОВЕРЕННОСТЬ ВЫДАНА НА ИМЯ КИМ В.С.")
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatFullName {
			found = true
			if got := "ДОВЕРЕННОСТЬ ВЫДАНА НА ИМЯ КИМ В.С."[s.Start:s.End]; got != "КИМ В.С." {
				t.Errorf("full_name value = %q, want %q", got, "КИМ В.С.")
			}
		}
	}
	if !found {
		t.Errorf("no full_name span for КИМ В.С.")
	}
}

// Point 1: lowercase full name after a name context keyword.
func TestFullNameLowercaseAfterContext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"клиент: ахметзянова зульфия ильгизовна", "ахметзянова зульфия ильгизовна"},
		{"ФИО: ахметзянова зульфия ильгизовна", "ахметзянова зульфия ильгизовна"},
		{"клиент представился как васильев-петренко артём", "васильев-петренко артём"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 2: four-token Turkic patronymic "name1 name2 кызы/оглы/улы".
func TestFullNameTurkicFourToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"АБДУЛЛАЕВА СЕВИЛЬ ФАРИД КЫЗЫ", "АБДУЛЛАЕВА СЕВИЛЬ ФАРИД КЫЗЫ"},
		{"Алиев Али Ахмед оглы", "Алиев Али Ахмед оглы"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 3: dative/instrumental with an unknown given name.
func TestFullNameDativeUnknownName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Доверенность выдана Ильгизу Рамилевичу Хабибуллину", "Ильгизу Рамилевичу Хабибуллину"},
		{"Претензия от Айгуль Маратовны Сафиной", "Айгуль Маратовны Сафиной"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 4: Latin full name after a context keyword.
func TestFullNameLatinWithContext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"my name is Tigran Avakyan", "Tigran Avakyan"},
		{"name: Ivanov Ivan", "Ivanov Ivan"},
		{"Заявитель Nguyen Van Long", "Nguyen Van Long"},
		{"Клиент Ivanov Ivan", "Ivanov Ivan"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 4 negative: Latin without context must not be detected.
func TestFullNameLatinNoContext(t *testing.T) {
	cases := []string{
		"Tigran Avakyan",
		"the client Tigran Avakyan",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatFullName) {
			t.Errorf("full_name should not detect %q, got %+v", c, res.Spans)
		}
	}
}

// Point 5: short non-Russian names in a dialogue reply.
func TestFullNameForeignDialogue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Оператор: Как к вам обращаться?\nКлиент: Нгуен Тхи Хоа", "Нгуен Тхи Хоа"},
		{"Данные для пропуска: ЛИ ЧЖИ ХУН", "ЛИ ЧЖИ ХУН"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 6: company names in guillemets are not full names.
func TestFullNameCompanyQuotesNegative(t *testing.T) {
	cases := []string{
		"компании «Пётр и Павел»",
		"ООО «Иванов и партнёры»",
		"АО «Пётр и Павел»",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatFullName) {
			t.Errorf("full_name should not detect company %q, got %+v", c, res.Spans)
		}
	}
}

// Point 6: maiden surname in parentheses is part of the full name span.
func TestFullNameMaidenSurnameInParens(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Сафина (Ганиева) Гульнара Ильдаровна", "Сафина (Ганиева) Гульнара Ильдаровна"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 12: "ДАТА РОЖДЕНИЯ" / "МЕСТО РОЖДЕНИЯ" in upper and mixed case are not
// full names.
func TestFullNameBirthPlaceLabelsNegative(t *testing.T) {
	cases := []string{
		"ДАТА РОЖДЕНИЯ: 14.07.1979",
		"ДаТа РоЖдЕнИя: 19.09.1988",
		"МЕСТО РОЖДЕНИЯ: КОПЕЙСК",
		"Дата рождения: 05.03.1985",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatFullName) {
			t.Errorf("full_name should not detect label %q, got %+v", c, res.Spans)
		}
	}
}

// Point 12: a famous person in the genitive case with a patronymic is not PII.
func TestFullNameFamousGenitiveWithPatronymic(t *testing.T) {
	// The surname is present right before the name+patronymic pair, so the
	// famous-person exception applies to the full three-word name.
	res := runPipeline(t, "Гагарина Юрия Алексеевича")
	if hasCategory(t, res, pii.CatFullName) {
		t.Errorf("famous person should not be PII: %q, got %+v", "Гагарина Юрия Алексеевича", res.Spans)
	}
}

// A bare name+patronymic pair without a surname is always PII: the
// famous-person exception requires the surname to be present too (see
// TestFullNameFamousGenitiveWithPatronymic, TestFullNameFamousWithPatronymic).
func TestFullNameBarePatronymicNoFamousException(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"endOfPhrase", "Фёдора Михайловича"},
		{"endOfPhraseNominative", "Пётр Андреевич"},
		{"actionVerbRight", "Александр Сергеевич позвонил вчера"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if !hasCategory(t, res, pii.CatFullName) {
				t.Errorf("bare name+patronymic without surname should be PII: %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

// Point 13: surname + unknown given name with a "зовут" context.
func TestFullNameSurnameUnknownNameWithZovut(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"зовут Каримов Бахтиёр", "Каримов Бахтиёр"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 13: foreign name after "для" / "на имя" context.
func TestFullNameForeignAfterDlya(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"доставка карты для Нгуен Тхи Лан", "Нгуен Тхи Лан"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 13: name + patronymic without a surname as a signature.
func TestFullNameNamePatronymicSignature(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Бабушка написала в чат: внучок, я забыла, пин-код от карты 5536 9104 6872 0190 это 4071 или 4017? Роза Мусаевна.", "Роза Мусаевна"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 3: "КАРТЫ ДЛЯ ЗАЧИСЛЕНИЯ" after a card number label is not a full name.
func TestFullNameCardLabelNegative(t *testing.T) {
	cases := []string{
		"ДОВЕРЕННОСТЬ ВЫДАНА НА ИМЯ ВАСИЛЬЕВА М.Д., НОМЕР КАРТЫ ДЛЯ ЗАЧИСЛЕНИЯ 4276036925814702.",
		"ДОВЕРЕННОСТЬ ВЫДАНА НА ИМЯ КИМ В.С., НОМЕР КАРТЫ ДЛЯ ЗАЧИСЛЕНИЯ 4276581470369255.",
		"ДОВЕРЕННОСТЬ ВЫДАНА НА ИМЯ ИВАНОВ П.С., НОМЕР КАРТЫ ДЛЯ ЗАЧИСЛЕНИЯ 4276036925814702.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		for _, s := range res.Spans {
			if s.Category == pii.CatFullName {
				val := c[s.Start:s.End]
				if val == "КАРТЫ ДЛЯ ЗАЧИСЛЕНИЯ" {
					t.Errorf("full_name should not detect %q in %q, got %+v", val, c, res.Spans)
				}
			}
		}
	}
}

// Point 4: "гражданин Республики" is not a full name.
func TestFullNameCitizenNegative(t *testing.T) {
	cases := []string{
		"В анкете клиента указано: гражданин Республики Казахстан, документ действителен.",
		"В анкете клиента указано: гражданка Республики Беларусь, документ действителен.",
		"Ахметова Айгуль Расуловна обратился в отделение, гражданин Республики Казахстан, документы на верификации.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		for _, s := range res.Spans {
			if s.Category == pii.CatFullName && citizenNameSpan(c, s.Start, s.End) {
				t.Errorf("full_name should not detect %q in %q, got %+v", c[s.Start:s.End], c, res.Spans)
			}
		}
	}
}

// citizenNameSpan reports whether the span [start,end) is a citizen phrase that
// must not be a full name.
func citizenNameSpan(text string, start, end int) bool {
	val := text[start:end]
	return val == "гражданин Республики" || val == "гражданка Республики"
}

// Point 4: a famous person's name is not suppressed when a subject marker
// appears to the left or another PII span is present in the same line.
func TestFullNameFamousNotSuppressedForClient(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Клиент Толстой Лев Николаевич, тел. +79161234567", "Толстой Лев Николаевич"},
		{"а клиент Лев Толстой оформил кредит", "Лев Толстой"},
		{"Клиент Пушкин Александр Сергеевич, дата рождения 06.06.1985", "Пушкин Александр Сергеевич"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
	}
}

// Point 4 negative: a famous person without a subject marker or other PII is
// still suppressed.
func TestFullNameFamousStillSuppressed(t *testing.T) {
	cases := []string{
		"Лев Толстой написал «Войну и мир»",
		"Пушкин написал стихи",
		"Поэт Александр Сергеевич Пушкин родился в Москве",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatFullName) {
			t.Errorf("famous person should not be PII: %q, got %+v", c, res.Spans)
		}
	}
}
