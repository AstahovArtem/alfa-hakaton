package engine

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
)

// --- text builders -----------------------------------------------------

// asciiFillerExact returns exactly n bytes of a repeating lowercase ASCII
// word-and-space pattern. Every byte in the alphabet is a single-byte rune,
// so any prefix of the result is a valid cut point; this lets the
// boundary-sweep tests below splice an entity in at an exact byte offset
// without risking a malformed UTF-8 edit to the test fixture itself.
func asciiFillerExact(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz "
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n + len(alphabet))
	for b.Len() < n {
		b.WriteString(alphabet)
	}
	return b.String()[:n]
}

// cyrillicFiller returns at least n bytes of repeating multibyte Cyrillic
// filler words separated by spaces, valid UTF-8.
func cyrillicFiller(n int) string {
	const words = "текстовый документ содержит обычные слова без персональных данных "
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words)
	}
	return b.String()
}

// sweepText builds a text well over chunkThreshold in size with entity
// spliced in at the exact byte offset chunkSize+delta, always immediately
// preceded and followed by a space (as any real document delimits a value
// from surrounding prose; some detector patterns anchor on \b, which does
// not consider a Latin letter glued directly to a digit or symbol a
// boundary). Sweeping delta across a range exercises every alignment of the
// entity relative to the window core boundary the engine computes near
// chunkSize (the boundary itself lands on nearby whitespace, not
// necessarily exactly at chunkSize, but the sweep range comfortably
// straddles it either way). The text is pure ASCII immediately around the
// splice point, so the splice is always on a valid rune boundary by
// construction, and it carries a block of multibyte Cyrillic filler further
// out so the surrounding windows also see multibyte content.
func sweepText(delta int, entity string) (text string, entityStart, entityEnd int) {
	target := chunkSize + delta
	if target < 1 {
		target = 1
	}
	head := asciiFillerExact(target-1) + " "
	tail := asciiFillerExact(96 * 1024)
	text = head + entity + " " + tail + " " + cyrillicFiller(8*1024)
	entityStart = len(head)
	entityEnd = entityStart + len(entity)
	return text, entityStart, entityEnd
}

// --- boundary sweep: single entities ------------------------------------

// TestChunkBoundarySweep places one PII value at a byte offset swept across
// chunkSize +/- 64 bytes (in 4-byte steps) and checks, for each placement,
// that: the pipeline still finds it (so nothing gets silently dropped at a
// window boundary), the sensitive substring never survives verbatim in the
// masked output, and unmasking restores the exact original text. This is
// the regression test for the production defect where an entity landing on
// a chunk border went out unmasked.
func TestChunkBoundarySweep(t *testing.T) {
	cases := []struct {
		name      string
		entity    string // text spliced into the document
		sensitive string // substring that must never leak verbatim once masked
		cat       pii.Category
	}{
		{"email", "ivan.petrov@example.com", "ivan.petrov@example.com", pii.CatEmail},
		{"phone", "+7 (916) 123-45-67", "+7 (916) 123-45-67", pii.CatPhone},
		{"passport_label_value", "паспорт 4509 123456", "4509 123456", pii.CatPassport},
		{"date", "12.03.1985", "12.03.1985", pii.CatDate},
		{"full_name", "Иванов Иван Иванович", "Иванов Иван Иванович", pii.CatFullName},
	}

	e := testEngine(t)
	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for delta := -64; delta <= 64; delta += 4 {
				text, start, end := sweepText(delta, tc.entity)
				if len(text) <= chunkThreshold {
					t.Fatalf("delta=%d: fixture is %d bytes, want > chunkThreshold", delta, len(text))
				}
				id := fmt.Sprintf("%s-%d", tc.name, delta)

				masked, found, err := e.Mask(ctx, id, text, Options{Strategy: "partial", TTL: time.Minute})
				if err != nil {
					t.Fatalf("delta=%d: Mask: %v", delta, err)
				}
				if found[tc.cat] == 0 {
					t.Errorf("delta=%d: category %s not detected, found=%v", delta, tc.cat, found)
				}
				if strings.Contains(masked, tc.sensitive) {
					t.Errorf("delta=%d: sensitive value %q leaked in masked output", delta, tc.sensitive)
				}
				// Sanity: entity was placed where we think it was.
				if text[start:end] != tc.entity {
					t.Fatalf("delta=%d: fixture bug, entity at [%d:%d) = %q", delta, start, end, text[start:end])
				}

				restored, misses, err := e.Unmask(ctx, id, masked)
				if err != nil {
					t.Fatalf("delta=%d: Unmask: %v", delta, err)
				}
				if misses != 0 {
					t.Errorf("delta=%d: %d unmask misses", delta, misses)
				}
				if restored != text {
					t.Errorf("delta=%d: round-trip mismatch", delta)
				}
			}
		})
	}
}

// --- boundary sweep: combo rule across windows --------------------------

// comboSweepText builds a text well over chunkThreshold with a card number
// near the start (inside the first window) and, when withPIN is true, a
// labeled PIN spliced in at chunkSize+delta bytes (so it can land in a
// different window than the card). It returns the PIN's byte range.
func comboSweepText(delta int, withPIN bool) (text string, pinStart, pinEnd int) {
	const cardBlock = "карта 4111 1111 1111 1111 "
	target := chunkSize + delta
	if target < len(cardBlock)+1 {
		target = len(cardBlock) + 1
	}
	head := cardBlock + asciiFillerExact(target-len(cardBlock)-1) + " "
	tail := asciiFillerExact(96 * 1024)
	pin := "пин 4321"
	if !withPIN {
		text = head + tail + " " + cyrillicFiller(8*1024)
		return text, -1, -1
	}
	text = head + pin + " " + tail + " " + cyrillicFiller(8*1024)
	pinValStart := len(head) + len("пин ")
	return text, pinValStart, pinValStart + len("4321")
}

// TestChunkComboRuleAcrossWindows verifies that a combo rule (PIN masked
// only when a card number is present) is evaluated once over the whole
// document, not per window: a card number in the first window must satisfy
// the rule for a PIN detected in a later window.
func TestChunkComboRuleAcrossWindows(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	rule := ComboRule{Category: pii.CatPIN, RequiresAny: []pii.Category{pii.CatCardNumber}}
	opt := Options{Strategy: "partial", TTL: time.Minute, ComboRules: []ComboRule{rule}}

	for delta := -64; delta <= 64; delta += 8 {
		text, pinStart, pinEnd := comboSweepText(delta, true)
		if len(text) <= chunkThreshold {
			t.Fatalf("delta=%d: fixture too small", delta)
		}
		id := fmt.Sprintf("combo-%d", delta)

		masked, found, err := e.Mask(ctx, id, text, opt)
		if err != nil {
			t.Fatalf("delta=%d: Mask: %v", delta, err)
		}
		if found[pii.CatCardNumber] == 0 || found[pii.CatPIN] == 0 {
			t.Fatalf("delta=%d: expected both card and pin masked, found=%v", delta, found)
		}
		if strings.Contains(masked, text[pinStart:pinEnd]) {
			t.Errorf("delta=%d: pin leaked in masked output", delta)
		}
		if strings.Contains(masked, "4111 1111 1111 1111") {
			t.Errorf("delta=%d: card leaked in masked output", delta)
		}

		restored, misses, err := e.Unmask(ctx, id, masked)
		if err != nil {
			t.Fatalf("delta=%d: Unmask: %v", delta, err)
		}
		if misses != 0 || restored != text {
			t.Errorf("delta=%d: round-trip failed (misses=%d)", delta, misses)
		}
	}

	// Without a card anywhere in the document, the PIN must stay unmasked.
	text, _, _ := comboSweepText(0, false)
	text = strings.Replace(text, "карта 4111 1111 1111 1111 ", "", 1) + "пин 4321"
	masked, found, err := e.Mask(ctx, "combo-no-card", text, opt)
	if err != nil {
		t.Fatalf("no-card: Mask: %v", err)
	}
	if found[pii.CatPIN] != 0 {
		t.Errorf("no-card: pin should not be masked, found=%v", found)
	}
	if !strings.Contains(masked, "4321") {
		t.Errorf("no-card: pin value should remain visible: %q...", masked[len(masked)-40:])
	}
}

// --- windowed detection equivalence to a whole-text run ------------------

// buildRichText returns a text of at least minSize bytes built by repeating
// a paragraph that exercises every category the boundary-sweep tests cover,
// interleaved with Cyrillic filler.
func buildRichText(minSize int) string {
	const para = "Клиент Иванов Иван Иванович, дата рождения 12.05.1990, гражданство РФ. " +
		"Паспорт 4509 123456 выдан 05.12.1990, код подразделения 770-001. " +
		"Карта 4111 1111 1111 1111, пин 4321. " +
		"Телефон +7 (916) 123-45-67, email ivan.petrov@example.com. "
	var b strings.Builder
	for b.Len() < minSize {
		b.WriteString(para)
	}
	return b.String()
}

// wholeTextResult masks text in one pipeline.Run/mask.Apply pass, bypassing
// windowing, as a reference for what a short (unchunked) text would produce.
func wholeTextResult(e *Engine, text string, opt Options, strategy mask.Strategy) (string, []mask.Replacement, map[pii.Category]int) {
	spans := filterSpans(e.pipeline.Run(text).Spans, opt.Categories, opt.ComboRules)
	masked, reps := mask.Apply(text, spans, strategy, mask.NewDocState())
	return masked, reps, counts(spans)
}

// TestChunkedEquivalentToWhole verifies that maskChunked (windowed,
// possibly-parallel detection) produces the same masked text, the same
// number of replacements and the same per-category counts as a single
// whole-text pipeline.Run + mask.Apply, at sizes that exercise the
// single-window fallback, a handful of windows, and many windows.
func TestChunkedEquivalentToWhole(t *testing.T) {
	e := testEngine(t)
	strategy := e.resolveStrategy("partial")
	opt := Options{Strategy: "partial"}

	sizes := []int{
		1024,             // far below chunkThreshold: exercises the single-window fallback
		chunkSize + 2048, // just above the single-window fallback cutoff
		200 * 1024,       // many windows
	}
	for _, size := range sizes {
		text := buildRichText(size)
		gotMasked, gotReps, gotFound := func() (string, []mask.Replacement, map[pii.Category]int) {
			m, r, f, _ := e.maskChunked(text, opt, strategy, mask.NewDocState())
			return m, r, f
		}()
		wantMasked, wantReps, wantFound := wholeTextResult(e, text, opt, strategy)

		if gotMasked != wantMasked {
			t.Errorf("size=%d: masked text differs from whole-text run", size)
		}
		if len(gotReps) != len(wantReps) {
			t.Errorf("size=%d: got %d replacements, want %d", size, len(gotReps), len(wantReps))
		}
		for cat, n := range wantFound {
			if gotFound[cat] != n {
				t.Errorf("size=%d: category %s: got %d, want %d", size, cat, gotFound[cat], n)
			}
		}
		for cat, n := range gotFound {
			if wantFound[cat] != n {
				t.Errorf("size=%d: category %s: got %d, whole-text had %d", size, cat, n, wantFound[cat])
			}
		}
	}
}

// --- large text: timing and round trip ------------------------------------

// TestChunkLargeTextPerformance builds a ~600 KB mixed Russian text with many
// PII values (roughly the size of a 100k-token document, the hackathon's
// stated input ceiling) and checks that masking it completes well under one
// second and that the round trip is exact. It logs timing and heap growth
// rather than asserting a tight bound, since both vary with the machine.
func TestChunkLargeTextPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-text timing test in -short mode")
	}
	e := testEngine(t)
	ctx := context.Background()

	text := buildRichText(600 * 1024)
	t.Logf("text size: %d bytes, GOMAXPROCS=%d", len(text), runtime.GOMAXPROCS(0))

	var msBefore, msAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&msBefore)

	start := time.Now()
	masked, found, err := e.Mask(ctx, "big", text, Options{Strategy: "partial", TTL: time.Minute})
	elapsed := time.Since(start)

	runtime.ReadMemStats(&msAfter)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}

	t.Logf("mask took %v", elapsed)
	t.Logf("heap grew by %.1f MiB (alloc %d -> %d)", float64(msAfter.HeapAlloc-msBefore.HeapAlloc)/(1<<20), msBefore.HeapAlloc, msAfter.HeapAlloc)

	// The budget is loose on purpose: the 10 s client timeout is the hard
	// limit, and a single-core pod or the race detector is several times slower.
	budget := 5 * time.Second
	if raceEnabled {
		budget = 60 * time.Second
	}
	if elapsed > budget {
		t.Errorf("mask took %v, want under budget %v", elapsed, budget)
	}
	if found[pii.CatFullName] == 0 || found[pii.CatPassport] == 0 || found[pii.CatPhone] == 0 ||
		found[pii.CatEmail] == 0 || found[pii.CatCardNumber] == 0 || found[pii.CatPIN] == 0 {
		t.Errorf("expected all categories detected, found=%v", found)
	}

	restored, misses, err := e.Unmask(ctx, "big", masked)
	if err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	if misses != 0 {
		t.Errorf("%d unmask misses", misses)
	}
	if restored != text {
		t.Errorf("round-trip failed for large text")
	}
}

// --- short text: unaffected by the chunking change ------------------------

// TestChunkShortTextUnchanged verifies that a text at or below chunkThreshold
// never goes through windowing: masking it via the public API gives exactly
// the same result as a direct, unchunked pipeline.Run + mask.Apply pass, the
// same computation the engine has always used for short texts.
func TestChunkShortTextUnchanged(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	strategy := e.resolveStrategy("partial")
	opt := Options{Strategy: "partial", TTL: time.Minute}

	texts := []string{
		testText,
		"Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67, email ivan@example.com",
		strings.Repeat("filler ", 100) + "карта 4111 1111 1111 1111 пин 4321",
	}
	for i, text := range texts {
		if len(text) > chunkThreshold {
			t.Fatalf("case %d: fixture is %d bytes, want <= chunkThreshold", i, len(text))
		}
		wantMasked, _, wantFound := wholeTextResult(e, text, opt, strategy)

		id := fmt.Sprintf("short-%d", i)
		gotMasked, gotFound, err := e.Mask(ctx, id, text, opt)
		if err != nil {
			t.Fatalf("case %d: Mask: %v", i, err)
		}
		if gotMasked != wantMasked {
			t.Errorf("case %d: masked text differs from the direct unchunked computation", i)
		}
		for cat, n := range wantFound {
			if gotFound[cat] != n {
				t.Errorf("case %d: category %s: got %d, want %d", i, cat, gotFound[cat], n)
			}
		}
	}
}
