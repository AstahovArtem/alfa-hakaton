package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
	"pdn-shield/internal/store"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st, err := store.NewMemory(key)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(st.Close)
	p := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		"partial":   mask.MustPartial(),
		"token":     mask.NewToken(),
		"synthetic": mask.NewSynthetic(),
	}
	return New(p, st, strategies)
}

func TestEngineMaskUnmask(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	text := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67"
	masked, counts, err := e.Mask(ctx, "doc1", text, Options{Strategy: "partial", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if counts[pii.CatFullName] != 1 || counts[pii.CatPassport] != 1 || counts[pii.CatPhone] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
	restored, misses, err := e.Unmask(ctx, "doc1", masked)
	if err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	if misses != 0 {
		t.Errorf("Unmask reported %d misses", misses)
	}
	if restored != text {
		t.Errorf("round-trip failed:\n got %q\nwant %q", restored, text)
	}
}

func TestEngineIdempotent(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	text := "карта 4111 1111 1111 1111"
	m1, _, err := e.Mask(ctx, "doc", text, Options{Strategy: "partial", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Mask 1: %v", err)
	}
	m2, _, err := e.Mask(ctx, "doc", text, Options{Strategy: "partial", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Mask 2: %v", err)
	}
	if m1 != m2 {
		t.Errorf("idempotency failed: %q vs %q", m1, m2)
	}
}

func TestEngineErrLooksLikeUnmask(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	text := "карта 4111 1111 1111 1111"
	masked, _, err := e.Mask(ctx, "doc", text, Options{Strategy: "partial", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	// Passing the masked text as the "new" text signals an unmask request.
	_, _, err = e.Mask(ctx, "doc", masked, Options{Strategy: "partial", TTL: time.Minute})
	if !errors.Is(err, ErrLooksLikeUnmask) {
		t.Errorf("expected ErrLooksLikeUnmask, got %v", err)
	}
}

func TestEngineUnmaskNotFound(t *testing.T) {
	e := testEngine(t)
	_, _, err := e.Unmask(context.Background(), "missing", "x")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestEngineCategoryFilter(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	text := "Клиент Иванов Иван Иванович, тел +7 (916) 123-45-67"
	masked, counts, err := e.Mask(ctx, "doc", text, Options{
		Strategy:   "partial",
		TTL:        time.Minute,
		Categories: []pii.Category{pii.CatPhone},
	})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if counts[pii.CatFullName] != 0 {
		t.Errorf("full_name should be filtered out, counts: %v", counts)
	}
	if counts[pii.CatPhone] != 1 {
		t.Errorf("phone should be present, counts: %v", counts)
	}
	// The full name should remain unmasked.
	if !contains(masked, "Иванов Иван Иванович") {
		t.Errorf("full name should remain unmasked: %q", masked)
	}
}

func TestEngineComboRules(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	rule := ComboRule{Category: pii.CatPIN, RequiresAny: []pii.Category{pii.CatCardNumber}}

	// No card number present -> pin not masked.
	masked, _, err := e.Mask(ctx, "doc1", "пин-код 4321", Options{
		Strategy:   "partial",
		TTL:        time.Minute,
		ComboRules: []ComboRule{rule},
	})
	if err != nil {
		t.Fatalf("Mask 1: %v", err)
	}
	if !contains(masked, "4321") {
		t.Errorf("pin should not be masked without card: %q", masked)
	}

	// Card present -> both masked.
	masked2, counts, err := e.Mask(ctx, "doc2", "карта 4111 1111 1111 1111 пин 4321", Options{
		Strategy:   "partial",
		TTL:        time.Minute,
		ComboRules: []ComboRule{rule},
	})
	if err != nil {
		t.Fatalf("Mask 2: %v", err)
	}
	if counts[pii.CatPIN] != 1 || counts[pii.CatCardNumber] != 1 {
		t.Errorf("both should be masked, counts: %v", counts)
	}
	if contains(masked2, "4321") || contains(masked2, "4111 1111 1111 1111") {
		t.Errorf("pin and card should be masked: %q", masked2)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
