package pii_test

import (
	"strings"
	"testing"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
)

// TestPipelineComposite runs a single text containing every supported category
// and verifies that the resolved spans are sorted, non-overlapping and cover
// the expected values.
func TestPipelineComposite(t *testing.T) {
	text := strings.Join([]string{
		"Иван Петров, дата рождения 12.05.1990, гражданство РФ.",
		"Паспорт 4509 123456 выдан 05.12.1990, код подразделения 770-001.",
		"Водительское удостоверение 77 12 345678, СНИЛС 112-233-445 95.",
		"Загранпаспорт 71 1234567.",
		"Email ivan.petrov@example.com, телефон +7 (916) 123-45-67.",
		"ИНН 500100732259, карта 4111 1111 1111 1111, CVV 123, ПИН-код 1234.",
	}, " ")

	expected := []struct {
		value    string
		category pii.Category
	}{
		{"12.05.1990", pii.CatBirthDate},
		{"РФ", pii.CatCitizenship},
		{"4509 123456", pii.CatPassport},
		{"05.12.1990", pii.CatPassportDate},
		{"770-001", pii.CatDivisionCode},
		{"77 12 345678", pii.CatDriverLicense},
		{"112-233-445 95", pii.CatSNILS},
		{"71 1234567", pii.CatForeignPassport},
		{"ivan.petrov@example.com", pii.CatEmail},
		{"+7 (916) 123-45-67", pii.CatPhone},
		{"500100732259", pii.CatINN},
		{"4111 1111 1111 1111", pii.CatCardNumber},
		{"123", pii.CatCVV},
		{"1234", pii.CatPIN},
	}

	p := pii.NewPipeline(detectors.Default()...)
	res := p.Run(text)

	assertSorted(t, res.Spans)
	assertNonOverlapping(t, res.Spans)
	assertCovered(t, text, res.Spans, expected)
}

// assertSorted fails when spans are not sorted by Start.
func assertSorted(t *testing.T, spans []pii.Span) {
	t.Helper()
	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].Start {
			t.Fatalf("spans not sorted: %+v", spans)
		}
	}
}

// assertNonOverlapping fails when any two spans overlap.
func assertNonOverlapping(t *testing.T, spans []pii.Span) {
	t.Helper()
	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].End {
			t.Fatalf("overlapping spans: %+v and %+v", spans[i-1], spans[i])
		}
	}
}

// assertCovered fails when an expected value is not covered by a span of the
// right category.
func assertCovered(t *testing.T, text string, spans []pii.Span, expected []struct {
	value    string
	category pii.Category
}) {
	t.Helper()
	for _, exp := range expected {
		found := false
		for _, s := range spans {
			if s.Category == exp.category && text[s.Start:s.End] == exp.value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(
				"value %q (category %s) not covered by a matching span; spans: %+v",
				exp.value,
				exp.category,
				spans,
			)
		}
	}
}
