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
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatFullName {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("full_name value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no full_name span for %q", c.in)
		}
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
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatFullName {
				found = true
				if s.Confidence != c.want {
					t.Errorf("confidence for %q = %v, want %v", c.in, s.Confidence, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no full_name span for %q", c.in)
		}
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
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatFullName {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("full_name value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no full_name span for %q", c.in)
		}
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
