package detectors

import "testing"

func TestLuhn(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4111 1111 1111 1111", true},
		{"4111 1111 1111 1112", false},
		{"5500 0000 0000 0004", true},
		{"1234", false},
		{"", false},
	}
	for _, c := range cases {
		if got := luhn(c.in); got != c.want {
			t.Errorf("luhn(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestINN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"3664069397", true},   // legal entity
		{"3664069398", false},  // bad checksum
		{"500100732259", true}, // individual
		{"500100732258", false},
		{"123", false},
		{"12345678901", false}, // 11 digits
	}
	for _, c := range cases {
		if got := inn(c.in); got != c.want {
			t.Errorf("inn(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSNILS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"112-233-445 95", true},
		{"112-233-445 96", false},
		{"000-029-999 00", true},
		{"123", false},
	}
	for _, c := range cases {
		if got := snils(c.in); got != c.want {
			t.Errorf("snils(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPassport(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4509 123456", true},
		{"0000 123456", false},
		{"4509 000000", false},
		{"4509123456", true},
	}
	for _, c := range cases {
		if got := passport(c.in); got != c.want {
			t.Errorf("passport(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPhone(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"+7 (916) 123-45-67", true},
		{"89161234567", true},
		{"79161234567", true},
		{"9161234567", false}, // 10 digits
		{"+1 916 123 45 67", false},
	}
	for _, c := range cases {
		if got := phone(c.in); got != c.want {
			t.Errorf("phone(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDate(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"12.05.1990", true},
		{"12/05/1990", true},
		{"1990-05-12", true},
		{"1990.05.12", true},
		{"2020.15.03", true}, // Y-D-M
		{"2020.03.15", true}, // Y-M-D
		{"05.12.1990", true},
		{"12 мая 1990", true},
		{"12 мая 1990 г.", true},
		{"12 мая 1990 года", true},
		{"31.02.2020", false}, // invalid day
		{"32.13.1990", false}, // invalid day and month in all interpretations
		{"12.05.1899", false}, // year too early
		{"12.05.2101", false}, // year too late
		{"1799", false},       // year alone is not a date
		{"12 мая", false},     // missing year
	}
	for _, c := range cases {
		if got := date(c.in); got != c.want {
			t.Errorf("date(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
