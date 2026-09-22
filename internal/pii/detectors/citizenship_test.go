package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestCitizenshipForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"colon", "Гражданство: Республика Корея", "Республика Корея"},
		{"dash", "Гражданство — Республика Беларусь", "Республика Беларусь"},
		{"applicant", "Гражданство заявителя: Таджикистан", "Таджикистан"},
		{"citizenF", "гражданка Республики Армения", "Республики Армения"},
		{"citizenM", "гражданин Узбекистана Юсупов Бахтиёр", "Узбекистана"},
		{"federation", "гражданин Российской Федерации", "Российской Федерации"},
		{"china", "гражданство Китайская Народная Республика", "Китайская Народная Республика"},
		{"kyrgyz", "гражданка Кыргызской Республики", "Кыргызской Республики"},
		{"vietnam", "гражданин Социалистической Республики Вьетнам", "Социалистической Республики Вьетнам"},
		{"romania", "гражданство Румыния", "Румыния"},
		{"rf", "гражданство РФ", "РФ"},
		{"english", "holds Azerbaijani citizenship", "Azerbaijani"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			found := false
			for _, s := range res.Spans {
				if s.Category == pii.CatCitizenship {
					found = true
					if got := c.in[s.Start:s.End]; got != c.want {
						t.Errorf("citizenship value for %q = %q, want %q", c.in, got, c.want)
					}
				}
			}
			if !found {
				t.Errorf("no citizenship span for %q", c.in)
			}
		})
	}
}

func TestCitizenshipDialog(t *testing.T) {
	in := "Оператор: Гражданство?\nКлиент: Вьетнам"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatCitizenship {
			found = true
			if got := in[s.Start:s.End]; got != "Вьетнам" {
				t.Errorf("dialog citizenship = %q, want %q", got, "Вьетнам")
			}
		}
	}
	if !found {
		t.Errorf("no citizenship span for dialog %q", in)
	}
}

func TestCitizenshipNegative(t *testing.T) {
	cases := []string{
		"гражданство",
		"гражданин",
		"гражданство не указано",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatCitizenship) {
			t.Errorf("citizenship should not detect %q, got %+v", c, res.Spans)
		}
	}
}
