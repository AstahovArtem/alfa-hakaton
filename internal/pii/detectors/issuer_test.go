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
		{"отделениемУФМС", "выдан отделением УФМС России по г. Москве", true},
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
		{"органВнутриОрганизации", "ИНН организации 7707083893. Пушкин написал стихи, отделение банка на Тверской."},
		{"отделениеБанка", "отделение банка на Тверской"},
		{"отделениеПочты", "Организация: ИНН 7707083893. Отделение почты на Ленина"},
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
		{
			"паспорт выдан ОУФМС России по г. Москве, отделом по району Хамовники",
			"ОУФМС России по г. Москве, отделом по району Хамовники",
		},
		{"выдан ГУ МВД России по г. Москве", "ГУ МВД России по г. Москве"},
		{"кем выдан: ОВД района Хамовники", "ОВД района Хамовники"},
		{
			"Паспорт выдан 15 мая 2010 года ОУФМС России по г. Москве, код подразделения 770-001",
			"ОУФМС России по г. Москве",
		},
		{"Паспорт выдан 5 марта 2015 г. ОУФМС России по г. Москве", "ОУФМС России по г. Москве"},
		{
			"Паспорт выдан пятнадцатого мая две тысячи десятого года ОУФМС России по г. Москве",
			"ОУФМС России по г. Москве",
		},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatPassportIssuer, c.in, c.want)
	}
}

func TestIssuerStopsBeforeNonContinuation(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			"Паспорт выдан ГУ МВД России по г. Санкт-Петербургу и Ленинградской области, копия страницы приложена к делу.",
			"ГУ МВД России по г. Санкт-Петербургу и Ленинградской области",
		},
		{
			"Паспорт выдан Отделом внутренних дел Кировского района г. Уфы, копия страницы приложена к делу.",
			"Отделом внутренних дел Кировского района г. Уфы",
		},
		{
			"Паспорт выдан УФМС России по Московской области в г. Балашиха, копия страницы приложена к делу.",
			"УФМС России по Московской области в г. Балашиха",
		},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatPassportIssuer, c.in, c.want)
	}
}

func TestIssuerAfterDateWithNumber(t *testing.T) {
	in := "паспорт 4001 №113578, выдан 31.01.2001 16 о/м Центрального р-на Санкт-Петербурга, код 782-016."
	assertSpanValue(t, runPipeline(t, in), pii.CatPassportIssuer, in, "16 о/м Центрального р-на Санкт-Петербурга")
}

func TestIssuerVyдалиV(t *testing.T) {
	in := "паспорт мне выдали двадцать первого августа две тысячи девятнадцатого года в МВД по Республике Башкортостан"
	assertSpanValue(t, runPipeline(t, in), pii.CatPassportIssuer, in, "МВД по Республике Башкортостан")
}

func TestIssuerOVDRaionaSokol(t *testing.T) {
	in := "Паспорт получен первого сентября две тысячи шестого года в ОВД района Сокол г. Москвы"
	assertSpanValue(t, runPipeline(t, in), pii.CatPassportIssuer, in, "ОВД района Сокол г. Москвы")
}
