package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

func TestCardHolderDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"uppercaseContext", "держатель карты IVAN IVANOV", true},
		{"uppercaseCardNumber", "IVAN IVANOV 4111 1111 1111 1111", true},
		{"uppercaseMiddleInitial", "IVAN I IVANOV 4111 1111 1111 1111", true},
		{"mixedContext", "держатель карты Ivan Ivanov", true},
		{"cardholderKeyword", "cardholder IVAN IVANOV", true},
		{"nameOnCard", "name on card IVAN IVANOV", true},
		{"rightContext", "IVAN IVANOV держатель карты", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatCardHolder); got != c.want {
				t.Errorf("card_holder detect %q = %v, want %v (spans: %+v)", c.in, got, c.want, res.Spans)
			}
		})
	}
}

func TestCardHolderNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"noContextNoCard", "IVAN IVANOV"},
		{"mixedNoContext", "Ivan Ivanov"},
		{"stopWords", "VISA MASTERCARD"},
		{"stopWordContext", "держатель карты VISA MASTERCARD"},
		{"singleWord", "IVAN"},
		{"badCardNumber", "IVAN IVANOV 4111 1111 1111 1112"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if got := hasCategory(t, res, pii.CatCardHolder); got {
				t.Errorf("card_holder should not detect %q, got spans: %+v", c.in, res.Spans)
			}
		})
	}
}

func TestCardHolderSpanExcludesContext(t *testing.T) {
	res := runPipeline(t, "держатель карты IVAN IVANOV")
	for _, s := range res.Spans {
		if s.Category == pii.CatCardHolder {
			if s.Start != 30 {
				t.Errorf("span should start at the name, got start=%d", s.Start)
			}
		}
	}
}

// Point 11: hyphenated surnames, "на имя" context, "CARDHOLDER:" label with a
// following "CARD" line not captured, and card_holder priority over full_name
// for uppercase Latin names.
func TestCardHolderForms(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"имя на карте ALEXANDRA VOLKOVA-BRANDT", "ALEXANDRA VOLKOVA-BRANDT"},
		{"Карта на имя ZULFIYA AKHMEDOVA", "ZULFIYA AKHMEDOVA"},
		{"Эмбоссированное имя: MARIIA KOVALENKO", "MARIIA KOVALENKO"},
		{"CARDHOLDER: OKSANA MELNYK\nCARD NO: 2201 9002 7463 8810", "OKSANA MELNYK"},
	}
	for _, c := range cases {
		assertSpanValue(t, runPipeline(t, c.in), pii.CatCardHolder, c.in, c.want)
	}
}

// Point 11: VALID THRU is not a cardholder; the name after it is.
func TestCardHolderValidThru(t *testing.T) {
	in := "На лицевой стороне: 5316 7402 8853 9041, VALID THRU 11/29, RUSLAN GAREEV. На обороте: 507."
	assertSpanValue(t, runPipeline(t, in), pii.CatCardHolder, in, "RUSLAN GAREEV")
}

// Point 11: an uppercase Latin name with a cardholder context is card_holder,
// not full_name.
func TestCardHolderPriorityOverFullName(t *testing.T) {
	in := "Эмбоссированное имя: MARIIA KOVALENKO. Номер карты: 4627 7930 0145 5828."
	res := runPipeline(t, in)
	if !hasCategory(t, res, pii.CatCardHolder) {
		t.Errorf("expected card_holder for %q, got %+v", in, res.Spans)
	}
	if hasCategory(t, res, pii.CatFullName) {
		t.Errorf("uppercase Latin name should be card_holder, not full_name: %+v", res.Spans)
	}
}
