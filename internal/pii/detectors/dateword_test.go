package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestDateWordsDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"genitive", "пятого марта 1985 года", "пятого марта 1985 года"},
		{"nominative", "пятое марта 1985", "пятое марта 1985"},
		{"fullYearWords", "двенадцатого мая тысяча девятьсот девяностого года", "двенадцатого мая тысяча девятьсот девяностого года"},
		{"fullYearWords2", "двадцать первого августа две тысячи девятнадцатого года", "двадцать первого августа две тысячи девятнадцатого года"},
		{"uppercase", "ПЯТОГО МАРТА 1985 ГОДА", "ПЯТОГО МАРТА 1985 ГОДА"},
		{"compoundDay", "двадцать первого марта 1985", "двадцать первого марта 1985"},
		{"thirtyFirst", "тридцать первого декабря 1999 года", "тридцать первого декабря 1999 года"},
		{"yearEightyFive", "пятого марта тысяча девятьсот восемьдесят пятого", "пятого марта тысяча девятьсот восемьдесят пятого"},
		{"yearTwoThousand", "пятого марта двухтысячного года", "пятого марта двухтысячного года"},
		{"yearTwoThousandFive", "пятого марта две тысячи пятого года", "пятого марта две тысячи пятого года"},
		{"abbrevMonth", "пятого мар 1985", "пятого мар 1985"},
		{"tailG", "пятого марта 1985 г.", "пятого марта 1985 г"},
		{"tailGShort", "пятого марта 1985 г", "пятого марта 1985 г"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			got, found := categoryValue(res, pii.CatDate, c.in)
			if !found {
				t.Fatalf("no date span for %q (spans: %+v)", c.in, res.Spans)
			}
			if got != c.want {
				t.Errorf("date value for %q = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestDateWordsNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"noYear", "пятого марта"},
		{"noMonth", "пятого 1985"},
		{"dayTooHigh", "тридцать второго марта 1985"},
		{"notADate", "первого числа каждого месяца"},
		{"insideWord", "двадцатьпервого марта 1985"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if hasCategory(t, res, pii.CatDate) || hasCategory(t, res, pii.CatBirthDate) {
				t.Errorf("expected no date span for %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

func TestDateWordsBirthReclassify(t *testing.T) {
	cases := []string{
		"дата рождения пятого марта 1985 года",
		"родился пятого марта 1985 года",
		"пятого марта 1985 года г.р.",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if !hasCategory(t, res, pii.CatBirthDate) {
			t.Errorf("expected birth_date for %q, got %+v", c, res.Spans)
		}
	}
}

func TestDateWordsPassportReclassify(t *testing.T) {
	cases := []string{
		"паспорт выдан пятого марта 1985 года",
		"дата выдачи пятого марта 1985 года",
	}
	for _, c := range cases {
		res := runPipeline(t, c)
		if !hasCategory(t, res, pii.CatPassportDate) {
			t.Errorf("expected passport_date for %q, got %+v", c, res.Spans)
		}
	}
}

func TestDateWordsMasking(t *testing.T) {
	in := "пятого марта 1985 года"
	res := runPipeline(t, in)
	got, found := categoryValue(res, pii.CatDate, in)
	if !found {
		t.Fatalf("no date span for %q", in)
	}
	if got != in {
		t.Errorf("date value = %q, want %q", got, in)
	}
}
