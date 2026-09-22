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
		{"orgBranchSentence", "Стихи Александра Пушкина читали в отделении банка по адресу ул. Тверская, 12. Заказ 1234567890 на сумму 15000 руб."},
		{"orgBranchWorkingHours", "Отделение банка по адресу ул. Тверская, 12 работает до 20:00"},
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
		{"Доставить: ул. Тверская, 12. Заказ 1234567890", "ул. Тверская, 12"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatAddress, c.in, c.want)
	}
}

func TestAddressFullStreetAfterPreposition(t *testing.T) {
	in := "Доставить на улица Гагарина, 5"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatAddress {
			found = true
			if got := in[s.Start:s.End]; got != "улица Гагарина, 5" {
				t.Errorf("address value = %q, want %q", got, "улица Гагарина, 5")
			}
		}
	}
	if !found {
		t.Errorf("no address span for %q", in)
	}
}

func TestAddressBareStreetHousingContext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"снимаю на Профсоюзной 96 корпус 2, квартира 15", "Профсоюзной 96 корпус 2, квартира 15"},
		{"живу на Тверской 5, квартира сорок два", "Тверской 5, квартира сорок два"},
		{"Реальный адрес доставки: Пушкина, 15, кв. 2", "Пушкина, 15, кв. 2"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatAddress, c.in, c.want)
	}
}

func TestAddressSecondAddress(t *testing.T) {
	in := "Прописка: 350000, Краснодарский край, г. Краснодар, ул. Красная, 176, кв. 9. Фактически проживаю по адресу Ленинский пр-т, 10, кв. 300."
	res := runPipeline(t, in)
	count := 0
	for _, s := range res.Spans {
		if s.Category == pii.CatAddress {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 address spans, got %d (%+v)", count, res.Spans)
	}
}

func TestAddressPostal(t *testing.T) {
	in := "630099 Новосибирск, а/я 145"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatAddress {
			found = true
			if got := in[s.Start:s.End]; got != "630099 Новосибирск, а/я 145" {
				t.Errorf("address value = %q, want %q", got, "630099 Новосибирск, а/я 145")
			}
		}
	}
	if !found {
		t.Errorf("no address span for %q", in)
	}
}

func TestAddressOrgFalsePositive(t *testing.T) {
	cases := []string{
		"Наш офис на ул. Ленина, 1 работает с 9 до 18, банкомат по адресу пр. Мира, 44 доступен круглосуточно.",
		"Отделение банка на Ленинском пр-те, 10 закрыто на ремонт",
		"Юридический адрес компании: 125009, Москва, Тверская ул., 7, офис 301.",
		"Wildberries пункт выдачи: Москва, ул. Бутлерова, 17.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if hasCategory(t, res, pii.CatAddress) {
			t.Errorf("address should not detect org address %q, got %+v", c, res.Spans)
		}
	}
}

func TestAddressHouseRangeAndParenCity(t *testing.T) {
	in := "ул. Кирова, 8-12 (Уфа)"
	res := runPipeline(t, in)
	found := false
	for _, s := range res.Spans {
		if s.Category == pii.CatAddress {
			found = true
			if got := in[s.Start:s.End]; got != "ул. Кирова, 8-12 (Уфа)" {
				t.Errorf("address value = %q, want %q", got, "ул. Кирова, 8-12 (Уфа)")
			}
		}
	}
	if !found {
		t.Errorf("no address span for %q", in)
	}
}
