package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestAddressDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"fullWithIndex", "адрес: 123456, г. Москва, ул. Ленина, д. 5, кв. 12", true},
		{"streetHouse", "ул. Ленина, д. 5, кв. 12", true},
		{"avenueNumber", "Ленинский проспект, 10", true},
		{"cityContext", "проживает в г. Казань, ул. Пушкина, д. 3", true},
		{"deliveryContext", "доставка по адресу: г. Санкт-Петербург, Невский проспект, д. 20", true},
		{"registered", "зарегистрирован по адресу: г. Новосибирск, ул. Советская, д. 7, кв. 3", true},
		{"cityStreetHouse", "г. Москва, ул. Ленина, д. 5", true},
		{"cityNoPrefix", "Москва, ул. Ленина, д. 5", true},
		{"region", "адрес: г. Краснодар, Краснодарский край, ул. Красная, д. 1", true},
		{"caseInsensitive", "АДРЕС: Г. МОСКВА, УЛ. ЛЕНИНА, Д. 5", true},
		{"obliqueCityBareStreet", "живёт в Казани, Кремлёвская 5", true},
		{"obliqueCityGenitive", "проживает в Москве, Тверская 10", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatAddress); got != c.want {
				t.Errorf("address detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestAddressNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"bankBranch", "отделение банка по адресу ул. Ленина, 1"},
		{"branch", "филиал банка: г. Москва, ул. Тверская, д. 10"},
		{"atm", "банкомат по адресу: г. Москва, ул. Ленина, д. 5"},
		{"extraOffice", "доп. офис: г. Москва, ул. Ленина, д. 5"},
		{"headOffice", "головной офис: г. Москва, ул. Ленина, д. 5"},
		{"doOffice", "ДО банка: г. Москва, ул. Ленина, д. 5"},
		{"cityOnly", "Москва — столица"},
		{"indexOnly", "индекс качества 123456"},
		{"streetOnly", "ул. Иванова"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatAddress); got {
				t.Errorf("address should not detect %q, got spans: %+v", c.in, res.Spans)
			}
		})
	}
}

func TestAddressSpanValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ул. Ленина, д. 5, кв. 12", "ул. Ленина, д. 5, кв. 12"},
		{"Ленинский проспект, 10", "Ленинский проспект, 10"},
		{"адрес: г. Москва, ул. Ленина, д. 5", "г. Москва, ул. Ленина, д. 5"},
		{"живёт в Казани, Кремлёвская 5", "Казани, Кремлёвская 5"},
	}
	for _, c := range cases {
		res := runPipeline(t, c.in)
		found := false
		for _, s := range res.Spans {
			if s.Category == pii.CatAddress {
				found = true
				if got := c.in[s.Start:s.End]; got != c.want {
					t.Errorf("address value for %q = %q, want %q", c.in, got, c.want)
				}
			}
		}
		if !found {
			t.Errorf("no address span for %q", c.in)
		}
	}
}
