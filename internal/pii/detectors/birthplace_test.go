package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestBirthplaceDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"placeBirth", "место рождения: г. Москва", true},
		{"bornIn", "родился в Москве", true},
		{"bornInCity", "родился в г. Казань", true},
		{"bornDate", "родился 12.05.1990 в Москве", true},
		{"bornWordDate", "родился 12 мая 1990 года в Казани", true},
		{"native", "уроженец города Казани", true},
		{"nativeF", "уроженка города Москвы", true},
		{"regionTail", "родился в г. Краснодар, Краснодарский край", true},
		{"caseInsensitive", "МЕСТО РОЖДЕНИЯ: Г. МОСКВА", true},
		{"ruralVillage", "Место рождения: с. Ивановка Рязанской области", true},
		{"ruralVillageNoComma", "родился в с. Ивановка Рязанской области", true},
		{"ruralStation", "место рождения: ст. Ивановка Рязанской области", true},
		{"ruralPoselok", "место рождения: пос. Ивановка Рязанской области", true},
		{"aul", "Место рождения: аул Хучни Республики Дагестан", true},
		{"derevnya", "Место рождения: д. Малиновка Брянской области", true},
		{"khutor", "место рождения: х. Заречный Краснодарского края", true},
		{"republicTwoWords", "место рождения: г. Владикавказ, Республика Северная Осетия", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatBirthPlace); got != c.want {
				t.Errorf("birth_place detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestBirthplaceNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"noContext", "Москва — столица"},
		{"noPlace", "родился в 1990 году"},
		{"noPlaceAfterPrefix", "родилась десятого октября тысяча девятьсот шестьдесят второго года в деревне"},
		{"noPlaceAfterPrefixPeriod", "родился в деревне. Далее текст"},
		{"noPlaceAfterPrefixComma", "родился в деревне, далее текст"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatBirthPlace); got {
				t.Errorf("birth_place should not detect %q, got spans: %+v", c.in, res.Spans)
			}
		})
	}
}

func TestBirthplaceSpanValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"место рождения: г. Москва", "г. Москва"},
		{"родился в Москве", "Москве"},
		{"родился 12.05.1990 в Москве", "Москве"},
		{"уроженец города Казани", "города Казани"},
		{"Место рождения: с. Ивановка Рязанской области", "с. Ивановка Рязанской области"},
		{"Место рождения: аул Хучни Республики Дагестан", "аул Хучни Республики Дагестан"},
		{"Место рождения: д. Малиновка Брянской области", "д. Малиновка Брянской области"},
		{"родился 5 марта 1985 г. в г. Казани", "г. Казани"},
		{"родилась 05.03.1985 г. в г. Казани", "г. Казани"},
		{"родился в 1985 году в г. Казани", "г. Казани"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatBirthPlace, c.in, c.want)
	}
}

func TestBirthplaceStopAtComma(t *testing.T) {
	in := "уроженка г. Еревана, гражданка Республики Армения"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatBirthPlace {
			found = true
			if got := in[s.Start:s.End]; got != "г. Еревана" {
				t.Errorf("birth_place value = %q, want %q", got, "г. Еревана")
			}
		}
	}
	if !found {
		t.Errorf("no birth_place span for %q", in)
	}
}

func TestBirthplaceAbbrevMonth(t *testing.T) {
	in := "родилась 05 мар 1985 в г. Набережные Челны, паспорт получала уже в Казани"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatBirthPlace {
			found = true
			if got := in[s.Start:s.End]; got != "г. Набережные Челны" {
				t.Errorf("birth_place value = %q, want %q", got, "г. Набережные Челны")
			}
		}
	}
	if !found {
		t.Errorf("no birth_place span for %q", in)
	}
}

func TestBirthplaceRegionAbbrev(t *testing.T) {
	in := "место рожд.: пос. Красный Яр Астраханской обл."
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatBirthPlace {
			found = true
			if got := in[s.Start:s.End]; got != "пос. Красный Яр Астраханской обл." {
				t.Errorf("birth_place value = %q, want %q", got, "пос. Красный Яр Астраханской обл.")
			}
		}
	}
	if !found {
		t.Errorf("no birth_place span for %q", in)
	}
}

func TestBirthplaceDashAndPronoun(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"место рождения — Челябинск", "Челябинск"},
		{"Родилась я в Ташкенте", "Ташкенте"},
		{"Родился в с. Верхние Киги, Башкирия", "с. Верхние Киги"},
		{"родился в деревне малые вяземы", "малые вяземы"},
		{"место рождения: село большие кайбицы", "село большие кайбицы"},
		{"родилась в пос. Шушенское", "пос. Шушенское"},
		{"уроженец г. Тихорецк", "г. Тихорецк"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatBirthPlace, c.in, c.want)
	}
}

func TestBirthplaceFalsePositive(t *testing.T) {
	in := "Она родилась в один день с бабушкой"
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should not detect %q, got %+v", in, res.Spans)
	}
}

func TestBirthplaceWordDateAndFullPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"родился пятого марта тысяча девятьсот восемьдесят пятого года в городе Тула", "Тула"},
		{"родилась десятого октября тысяча девятьсот шестьдесят второго года в деревне Малые Вяземы", "Малые Вяземы"},
		{"Место рождения: с. Большие Кайбицы Кайбицкого района Татарской АССР.", "с. Большие Кайбицы Кайбицкого района Татарской АССР"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatBirthPlace, c.in, c.want)
	}
}

func TestBirthplaceRodAbbrev(t *testing.T) {
	in := "Клиент Степанов Б. Н., род. 12 окт 1969 в г. Орёл."
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should detect %q, got %+v", in, res.Spans)
	}
}

func TestBirthplaceRodNotInGorod(t *testing.T) {
	in := "Дата рожд.: 09-11-2001. Прописка: мкр. Северный, д. 3, кв. 45, г. Белгород. Ф.И.О.: Остапенко Дарина Олеговна."
	res := runPipeline(t, in)
	if hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should not detect %q, got %+v", in, res.Spans)
	}
}

// Point 5: a famous person's birth place is not personal data.
func TestBirthplaceFamousPersonNegative(t *testing.T) {
	cases := []string{
		"Поэт Александр Сергеевич Пушкин родился в Москве.",
		"Лев Толстой родился в Ясной Поляне.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatBirthPlace) {
			t.Errorf("birth_place should not detect famous person %q, got %+v", c, res.Spans)
		}
	}
}

// Point 5: a client with a famous person's name still has a birth place.
func TestBirthplaceFamousNameClient(t *testing.T) {
	in := "Клиент Пушкин Александр Сергеевич родился в Москве."
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatBirthPlace) {
		t.Errorf("birth_place should detect client %q, got %+v", in, res.Spans)
	}
}
