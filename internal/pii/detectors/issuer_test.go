package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestIssuerDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"oufms", "паспорт выдан ОУФМС России по г. Москве, отделом по району Хамовники", true},
		{"guMvd", "выдан ГУ МВД России по г. Москве", true},
		{"kемВыдан", "кем выдан: ОВД района Хамовники", true},
		{"органВыдачи", "орган выдачи: УФМС России по г. Казани", true},
		{"отдел", "паспорт выдан Отделом УФМС России по г. Москве", true},
		{"управление", "выдан Управлением МВД России по г. Москве", true},
		{"caseInsensitive", "ПАСПОРТ ВЫДАН ОУФМС РОССИИ ПО Г. МОСКВЕ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPassportIssuer); got != c.want {
				t.Errorf("passport_issuer detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestIssuerNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"noStartWord", "паспорт выдан 12.05.1990"},
		{"noContext", "ОУФМС России по г. Москве"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatPassportIssuer); got {
				t.Errorf("passport_issuer should not detect %q, got spans: %+v", c.in, res.Spans)
			}
		})
	}
}

func TestIssuerSpanValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"паспорт выдан ОУФМС России по г. Москве, отделом по району Хамовники", "ОУФМС России по г. Москве, отделом по району Хамовники"},
		{"выдан ГУ МВД России по г. Москве", "ГУ МВД России по г. Москве"},
		{"кем выдан: ОВД района Хамовники", "ОВД района Хамовники"},
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatPassportIssuer {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("passport_issuer value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no passport_issuer span for %q", c.in)
		}
	}
}

func TestIssuerStopsBeforeNonContinuation(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Паспорт выдан ГУ МВД России по г. Санкт-Петербургу и Ленинградской области, копия страницы приложена к делу.", "ГУ МВД России по г. Санкт-Петербургу и Ленинградской области"},
		{"Паспорт выдан Отделом внутренних дел Кировского района г. Уфы, копия страницы приложена к делу.", "Отделом внутренних дел Кировского района г. Уфы"},
		{"Паспорт выдан УФМС России по Московской области в г. Балашиха, копия страницы приложена к делу.", "УФМС России по Московской области в г. Балашиха"},
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatPassportIssuer {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("passport_issuer value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no passport_issuer span for %q", c.in)
		}
	}
}
