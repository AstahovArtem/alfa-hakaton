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
