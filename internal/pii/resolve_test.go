package pii

import "testing"

func TestResolveSortsAndDedups(t *testing.T) {
	spans := []Span{
		{Start: 10, End: 20, Category: CatPhone, Confidence: 0.5},
		{Start: 5, End: 15, Category: CatEmail, Confidence: 0.9},
		{Start: 30, End: 40, Category: CatINN, Confidence: 0.8},
	}
	got := Resolve(spans)
	if len(got) != 2 {
		t.Fatalf("expected 2 spans, got %d: %+v", len(got), got)
	}
	if got[0].Start != 5 || got[0].Category != CatEmail {
		t.Errorf("first span wrong: %+v", got[0])
	}
	if got[1].Start != 30 {
		t.Errorf("second span wrong: %+v", got[1])
	}
}

func TestResolveEqualConfidenceLongerWins(t *testing.T) {
	spans := []Span{
		{Start: 0, End: 10, Category: CatPhone, Confidence: 0.9},
		{Start: 2, End: 20, Category: CatEmail, Confidence: 0.9},
	}
	got := Resolve(spans)
	if len(got) != 1 {
		t.Fatalf("expected 1 span, got %d", len(got))
	}
	if got[0].End != 20 {
		t.Errorf("longer span should win, got %+v", got[0])
	}
}

func TestCounts(t *testing.T) {
	res := Result{Spans: []Span{
		{Category: CatPhone},
		{Category: CatPhone},
		{Category: CatEmail},
	}}
	c := res.Counts()
	if c[CatPhone] != 2 || c[CatEmail] != 1 {
		t.Errorf("counts wrong: %+v", c)
	}
}
