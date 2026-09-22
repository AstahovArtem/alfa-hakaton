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
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatBirthPlace {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("birth_place value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no birth_place span for %q", c.in)
		}
	}
}
