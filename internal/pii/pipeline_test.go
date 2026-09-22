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

	// Spans must be sorted by Start.
	for i := 1; i < len(res.Spans); i++ {
		if res.Spans[i].Start < res.Spans[i-1].Start {
			t.Fatalf("spans not sorted: %+v", res.Spans)
		}
	}

	// Spans must not overlap.
	for i := 1; i < len(res.Spans); i++ {
		if res.Spans[i].Start < res.Spans[i-1].End {
			t.Fatalf("overlapping spans: %+v and %+v", res.Spans[i-1], res.Spans[i])
		}
	}

	// Every expected value must be covered by a span of the right category.
	for _, exp := range expected {
		found := false
		for _, s := range res.Spans {
			if s.Category == exp.category && text[s.Start:s.End] == exp.value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("value %q (category %s) not covered by a matching span; spans: %+v", exp.value, exp.category, res.Spans)
		}
	}
}
