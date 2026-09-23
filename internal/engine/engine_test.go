package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
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

const testText = "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67"

// testSystemID is the caller identity used across engine tests that do not
// specifically exercise ownership/access-control behaviour, so a record
// created by one call in a test remains accessible to a later call in the
// same test.
const testSystemID = "test-system"

func TestEngineMaskUnmask(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	text := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67"
	opt := Options{Strategy: "partial", TTL: time.Minute, SystemID: testSystemID}
	masked, counts, err := e.Mask(ctx, "doc1", text, opt)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if counts[pii.CatFullName] != 1 || counts[pii.CatPassport] != 1 || counts[pii.CatPhone] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
	restored, misses, err := e.Unmask(ctx, "doc1", masked, opt)
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
	opt := Options{Strategy: "partial", TTL: time.Minute, SystemID: testSystemID}
	m1, _, err := e.Mask(ctx, "doc", text, opt)
	if err != nil {
		t.Fatalf("Mask 1: %v", err)
	}
	m2, _, err := e.Mask(ctx, "doc", text, opt)
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
	opt := Options{Strategy: "partial", TTL: time.Minute, SystemID: testSystemID}
	masked, _, err := e.Mask(ctx, "doc", text, opt)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	// Passing the masked text as the "new" text signals an unmask request.
	_, _, err = e.Mask(ctx, "doc", masked, opt)
	if !errors.Is(err, ErrLooksLikeUnmask) {
		t.Errorf("expected ErrLooksLikeUnmask, got %v", err)
	}
}

func TestEngineUnmaskNotFound(t *testing.T) {
	e := testEngine(t)
	_, _, err := e.Unmask(context.Background(), "missing", "x", Options{SystemID: testSystemID})
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
		SystemID:   testSystemID,
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
		SystemID:   testSystemID,
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
		SystemID:   testSystemID,
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

func TestEngineProcessContract(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	opt := Options{Strategy: "partial", TTL: time.Minute, Unmask: true, SystemID: testSystemID}

	masked := processMask(t, e, ctx, opt)
	processIdempotent(t, e, ctx, opt, masked)
	processUnmask(t, e, ctx, opt, masked)
	processDiffers(t, e, ctx, opt)
}

// processMask masks testText under id "p1" and returns the masked result.
func processMask(t *testing.T, e *Engine, ctx context.Context, opt Options) string {
	t.Helper()
	res, err := e.Process(ctx, "p1", testText, opt)
	if err != nil {
		t.Fatalf("Process mask: %v", err)
	}
	if res.Unmasked || res.Found[pii.CatFullName] != 1 {
		t.Errorf("mask result: %+v", res)
	}
	return res.Result
}

// processIdempotent verifies that re-masking the same payload returns the stored
// mask.
func processIdempotent(t *testing.T, e *Engine, ctx context.Context, opt Options, masked string) {
	t.Helper()
	res2, err := e.Process(ctx, "p1", testText, opt)
	if err != nil {
		t.Fatalf("Process idempotent: %v", err)
	}
	if res2.Result != masked {
		t.Errorf("idempotent result = %q, want %q", res2.Result, masked)
	}
}

// processUnmask verifies that passing the stored mask restores the original
// text.
func processUnmask(t *testing.T, e *Engine, ctx context.Context, opt Options, masked string) {
	t.Helper()
	res3, err := e.Process(ctx, "p1", masked, opt)
	if err != nil {
		t.Fatalf("Process unmask: %v", err)
	}
	if !res3.Unmasked || res3.Result != testText {
		t.Errorf("unmask result: %+v", res3)
	}
}

// processDiffers verifies that a payload matching neither the stored mask nor
// the original text is treated as fresh content: masked with the caller's
// strategy (here, containing no PII, so it comes back unchanged) rather than
// returned as an unmask attempt with misses.
func processDiffers(t *testing.T, e *Engine, ctx context.Context, opt Options) {
	t.Helper()
	res4, err := e.Process(ctx, "p1", "совсем другой текст", opt)
	if err != nil {
		t.Fatalf("Process differs: %v", err)
	}
	if res4.Result != "совсем другой текст" {
		t.Errorf("differs result: %+v", res4)
	}
	if res4.Unmasked {
		t.Errorf("differs result should not be marked Unmasked: %+v", res4)
	}
}

func TestEngineProcessUnknownID(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	res, err := e.Process(ctx, "missing", "текст без пд", Options{Strategy: "partial", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Result != "текст без пд" {
		t.Errorf("result = %q", res.Result)
	}
}

func TestEngineProcessPartialRestore(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	opt := Options{Strategy: "partial", TTL: time.Minute, Unmask: true, SystemID: testSystemID}

	// Mask a text with two PII values so the record has two replacements.
	text := "Клиент Иванов Иван Иванович, тел +7 (916) 123-45-67"
	res, err := e.Process(ctx, "p", text, opt)
	if err != nil {
		t.Fatalf("Process mask: %v", err)
	}
	masked := res.Result

	// Build a payload that contains one masked value (restorable) plus a
	// non-matching tail, so Restore applies one replacement and misses one.
	phoneMask := masked[strings.Index(masked, "+7"):]
	payload := phoneMask + " и ещё что-то"
	pres, err := e.Process(ctx, "p", payload, opt)
	if err != nil {
		t.Fatalf("Process partial: %v", err)
	}
	if !pres.Unmasked {
		t.Errorf("expected Unmasked=true, got %+v", pres)
	}
	if pres.Misses == 0 {
		t.Errorf("expected misses > 0, got %d", pres.Misses)
	}
	if pres.Result == payload {
		t.Errorf("expected restored text, got payload as-is: %q", pres.Result)
	}
	if !strings.Contains(pres.Result, "+7 (916) 123-45-67") {
		t.Errorf("expected restored phone in result: %q", pres.Result)
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

func TestEngineChunkedLargeText(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()

	// Build a ~400 KiB text with repeated PII values separated by sentences.
	var b strings.Builder
	line := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67. "
	for b.Len() < 400*1024 {
		b.WriteString(line)
	}
	text := b.String()

	opt := Options{Strategy: "partial", TTL: time.Minute, SystemID: testSystemID}
	masked, found, err := e.Mask(ctx, "big", text, opt)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if found[pii.CatFullName] == 0 || found[pii.CatPassport] == 0 || found[pii.CatPhone] == 0 {
		t.Errorf("expected PII found in large text, counts: %v", found)
	}

	// Whole-text processing must yield the same number of spans per category.
	res := e.pipeline.Run(text)
	whole := counts(filterSpans(res.Spans, nil, nil))
	for cat, n := range whole {
		if found[cat] != n {
			t.Errorf("category %s: chunked=%d whole=%d", cat, found[cat], n)
		}
	}

	// Round-trip must restore the original text.
	assertRoundTrip(t, ctx, e, "big", masked, text, opt)
}

// assertRoundTrip unmaskes masked and verifies it restores want with no misses.
func assertRoundTrip(t *testing.T, ctx context.Context, e *Engine, id, masked, want string, opt Options) {
	t.Helper()
	restored, misses, err := e.Unmask(ctx, id, masked, opt)
	if err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	if misses != 0 {
		t.Errorf("Unmask reported %d misses", misses)
	}
	if restored != want {
		t.Errorf("round-trip failed for large text")
	}
}

// countingStore wraps a Store and counts Load/Save/SaveNew calls.
type countingStore struct {
	store.Store
	loads    atomic.Int64
	saves    atomic.Int64
	saveNews atomic.Int64
}

func (c *countingStore) Load(ctx context.Context, id string) (store.Record, bool, error) {
	c.loads.Add(1)
	return c.Store.Load(ctx, id)
}

func (c *countingStore) Save(ctx context.Context, id string, rec store.Record, ttl time.Duration) error {
	c.saves.Add(1)
	return c.Store.Save(ctx, id, rec, ttl)
}

func (c *countingStore) SaveNew(ctx context.Context, id string, rec store.Record, ttl time.Duration) (bool, error) {
	c.saveNews.Add(1)
	return c.Store.SaveNew(ctx, id, rec, ttl)
}

// TestProcessStoreCallCount verifies Process performs exactly 1 GET + 1 SET for
// a mask and exactly 1 GET for an unmask.
func TestProcessStoreCallCount(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	ms, err := store.NewMemory(key)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(ms.Close)
	cs := &countingStore{Store: ms}

	p := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		"partial":   mask.MustPartial(),
		"token":     mask.NewToken(),
		"synthetic": mask.NewSynthetic(),
	}
	e := New(p, cs, strategies)
	ctx := context.Background()
	opt := Options{Strategy: "partial", TTL: time.Minute, Unmask: true, SystemID: testSystemID}

	// Mask: 1 GET (miss) + 1 SET (SaveNew, since the id is new).
	res := processOrFail(t, ctx, e, "c1", testText, opt)
	if cs.loads.Load() != 1 || cs.saveNews.Load() != 1 {
		t.Errorf("mask: loads=%d saveNews=%d, want 1/1", cs.loads.Load(), cs.saveNews.Load())
	}
	masked := res.Result

	// Unmask: 1 GET only.
	cs.loads.Store(0)
	cs.saveNews.Store(0)
	res2 := processOrFail(t, ctx, e, "c1", masked, opt)
	if !res2.Unmasked || res2.Result != testText {
		t.Errorf("unmask result: %+v", res2)
	}
	if cs.loads.Load() != 1 || cs.saveNews.Load() != 0 {
		t.Errorf("unmask: loads=%d saveNews=%d, want 1/0", cs.loads.Load(), cs.saveNews.Load())
	}
}

// processOrFail runs e.Process and fails the test on error.
func processOrFail(t *testing.T, ctx context.Context, e *Engine, id, text string, opt Options) ProcessResult {
	t.Helper()
	res, err := e.Process(ctx, id, text, opt)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return res
}

// TestEngineIDDocumentRoundTrip verifies that masking an id_document value with
// each strategy and unmasking restores the original text.
func TestEngineIDDocumentRoundTrip(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	texts := []string{
		"военный билет АБ 1234567",
		"вид на жительство 82 №1234567",
		"свидетельство о рождении II-МЮ №123456",
	}
	for _, strategy := range []string{"partial", "full", "token", "synthetic"} {
		for i, text := range texts {
			roundTripIDDocument(t, ctx, e, strategy, itoa(i), text)
		}
	}
}

// roundTripIDDocument masks text with strategy, unmasks it and verifies the
// original is restored with no misses.
func roundTripIDDocument(t *testing.T, ctx context.Context, e *Engine, strategy, id, text string) {
	t.Helper()
	opt := Options{Strategy: strategy, TTL: time.Minute, SystemID: testSystemID}
	masked, counts, err := e.Mask(ctx, id, text, opt)
	if err != nil {
		t.Fatalf("Mask(%s): %v", strategy, err)
	}
	if counts[pii.CatIDDocument] != 1 {
		t.Errorf("Mask(%s) counts = %v, want id_document=1", strategy, counts)
	}
	restored, misses, err := e.Unmask(ctx, id, masked, opt)
	if err != nil {
		t.Fatalf("Unmask(%s): %v", strategy, err)
	}
	if misses != 0 {
		t.Errorf("Unmask(%s) reported %d misses", strategy, misses)
	}
	if restored != text {
		t.Errorf("round-trip(%s) failed:\n got %q\nwant %q", strategy, restored, text)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
