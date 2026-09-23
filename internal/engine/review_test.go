package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
	"pdn-shield/internal/store"
)

// TestProcessUnmaskFalseNeverRestores is the A3 regression: with opt.Unmask
// false, no payload shape (prefix of the mask, suffix, a single masked
// token, a partial answer) may ever cause a restore. Every such call must
// come back as a fresh mask of the payload, and none of the results may
// contain the original PII values.
func TestProcessUnmaskFalseNeverRestores(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	opt := Options{Strategy: "token", TTL: time.Minute, Unmask: false, SystemID: testSystemID}

	res, err := e.Process(ctx, "noUnmask", testText, opt)
	if err != nil {
		t.Fatalf("Process mask: %v", err)
	}
	masked := res.Result
	if masked == testText {
		t.Fatalf("masked result equals original")
	}

	payloads := map[string]string{
		"stored mask itself": masked,
		"prefix of mask":     masked[:len(masked)/2],
		"suffix of mask":     masked[len(masked)/2:],
		"single token":       firstToken(masked),
		"partial answer":     "Клиент " + firstToken(masked) + " хочет уточнить статус.",
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			pres, err := e.Process(ctx, "noUnmask", payload, opt)
			if err != nil {
				t.Fatalf("Process(%s): %v", name, err)
			}
			if pres.Unmasked {
				t.Errorf("Process(%s) set Unmasked=true, want false: %+v", name, pres)
			}
			assertNoOriginalValues(t, pres.Result)
		})
	}
}

// firstToken returns the first "[...]" token in s, or s itself if none.
func firstToken(s string) string {
	start := strings.Index(s, "[")
	if start < 0 {
		return s
	}
	end := strings.Index(s[start:], "]")
	if end < 0 {
		return s
	}
	return s[start : start+end+1]
}

// assertNoOriginalValues fails when result contains any of the raw PII
// values from testText.
func assertNoOriginalValues(t *testing.T, result string) {
	t.Helper()
	for _, v := range []string{"Иванов", "4509 123456", "916) 123-45-67"} {
		if strings.Contains(result, v) {
			t.Errorf("result leaked original value %q: %q", v, result)
		}
	}
}

// TestProcessZeroMatchMasksFresh is the A5 regression: a payload that
// matches neither the stored original nor the stored mask, and restores zero
// replacements, must be masked fresh rather than returned unchanged (which
// would leak any PII the payload happens to contain).
func TestProcessZeroMatchMasksFresh(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	opt := Options{Strategy: "token", TTL: time.Minute, Unmask: true, SystemID: testSystemID}

	if _, err := e.Process(ctx, "zeroMatch", testText, opt); err != nil {
		t.Fatalf("Process mask: %v", err)
	}

	// A payload unrelated to the stored mask, but carrying its own PII.
	payload := "Новый клиент Петров Пётр Петрович, тел +7 (925) 555-11-22"
	res, err := e.Process(ctx, "zeroMatch", payload, opt)
	if err != nil {
		t.Fatalf("Process zero-match: %v", err)
	}
	if res.Result == payload {
		t.Fatalf("zero-match payload returned unchanged: PII leak: %q", res.Result)
	}
	if strings.Contains(res.Result, "Петров") || strings.Contains(res.Result, "925) 555-11-22") {
		t.Errorf("zero-match result leaks PII: %q", res.Result)
	}
	if res.Unmasked {
		t.Errorf("zero-match result should not be marked Unmasked: %+v", res)
	}

	// The stored record must be untouched: a genuine unmask retry with the
	// original mask must still work afterwards.
	orig, err := e.Process(ctx, "zeroMatch", testText, opt)
	if err != nil {
		t.Fatalf("Process idempotent after zero-match: %v", err)
	}
	restore, err := e.Process(ctx, "zeroMatch", orig.Result, opt)
	if err != nil {
		t.Fatalf("Process restore after zero-match: %v", err)
	}
	if !restore.Unmasked || restore.Result != testText {
		t.Errorf("record was corrupted by the zero-match call: %+v", restore)
	}
}

// TestOwnershipProcessForeignRecordNeverOverwritten is the A4 regression for
// /process: when system B calls Process with an id already owned by system A,
// it must get a fresh mask of its own payload, never A's stored mask or
// restored content, and A's record must survive untouched.
func TestOwnershipProcessForeignRecordNeverOverwritten(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	optA := Options{Strategy: "token", TTL: time.Minute, Unmask: true, SystemID: "systemA", DefaultSystemID: "checker"}
	optB := Options{Strategy: "token", TTL: time.Minute, Unmask: true, SystemID: "systemB", DefaultSystemID: "checker"}

	resA, err := e.Process(ctx, "shared", testText, optA)
	if err != nil {
		t.Fatalf("Process as A: %v", err)
	}

	// B uses the same id with different content.
	bPayload := "Клиент Смирнова Мария Игоревна, тел +7 (901) 000-11-22"
	resB, err := e.Process(ctx, "shared", bPayload, optB)
	if err != nil {
		t.Fatalf("Process as B: %v", err)
	}
	if resB.Result == bPayload {
		t.Fatalf("B's payload leaked unchanged: %q", resB.Result)
	}
	if strings.Contains(resB.Result, "Смирнова") {
		t.Errorf("B's result leaks B's own PII (masking failed): %q", resB.Result)
	}
	if resB.Result == resA.Result {
		t.Errorf("B received A's stored mask")
	}

	// B tries to unmask using A's mask under the same id: must not restore
	// A's data.
	resB2, err := e.Process(ctx, "shared", resA.Result, optB)
	if err != nil {
		t.Fatalf("Process B with A's mask: %v", err)
	}
	if resB2.Unmasked {
		t.Errorf("B was able to unmask A's record: %+v", resB2)
	}
	if strings.Contains(resB2.Result, "Иванов") || strings.Contains(resB2.Result, "4509 123456") {
		t.Errorf("B's attempt leaked A's PII: %q", resB2.Result)
	}

	// A's record must still work normally afterwards.
	resA2, err := e.Process(ctx, "shared", testText, optA)
	if err != nil {
		t.Fatalf("Process idempotent as A: %v", err)
	}
	if resA2.Result != resA.Result {
		t.Errorf("A's record was disturbed by B's calls: %q vs %q", resA2.Result, resA.Result)
	}
	restoreA, err := e.Process(ctx, "shared", resA.Result, optA)
	if err != nil {
		t.Fatalf("Process restore as A: %v", err)
	}
	if !restoreA.Unmasked || restoreA.Result != testText {
		t.Errorf("A could not restore its own record after B's foreign access: %+v", restoreA)
	}
}

// TestOwnershipUnmaskForeignRecordNotFound is the A4 regression for /unmask:
// a system that does not own the record gets ErrNotFound, not the restored
// content or a store error.
func TestOwnershipUnmaskForeignRecordNotFound(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	optA := Options{Strategy: "token", TTL: time.Minute, Unmask: true, SystemID: "systemA", DefaultSystemID: "checker"}
	optB := Options{Strategy: "token", TTL: time.Minute, Unmask: true, SystemID: "systemB", DefaultSystemID: "checker"}

	masked, _, err := e.Mask(ctx, "ownerDoc", testText, optA)
	if err != nil {
		t.Fatalf("Mask as A: %v", err)
	}

	_, _, err = e.Unmask(ctx, "ownerDoc", masked, optB)
	if err == nil {
		t.Fatalf("expected an error unmasking A's record as B")
	}
	if !isNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestOwnershipMaskEndpointNeverOverwritesForeignRecord is the A4 regression
// for /mask: MaskEx on an id owned by another system must fail with
// ErrForeignRecord and must never overwrite the foreign record.
func TestOwnershipMaskEndpointNeverOverwritesForeignRecord(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	optA := Options{Strategy: "token", TTL: time.Minute, SystemID: "systemA", DefaultSystemID: "checker"}
	optB := Options{Strategy: "token", TTL: time.Minute, SystemID: "systemB", DefaultSystemID: "checker"}

	resA, err := e.MaskEx(ctx, "shared2", testText, optA)
	if err != nil {
		t.Fatalf("MaskEx as A: %v", err)
	}

	_, err = e.MaskEx(ctx, "shared2", "текст системы B", optB)
	if !isForeignRecord(err) {
		t.Fatalf("expected ErrForeignRecord, got %v", err)
	}

	// A's record must be untouched.
	resA2, err := e.MaskEx(ctx, "shared2", testText, optA)
	if err != nil {
		t.Fatalf("MaskEx idempotent as A: %v", err)
	}
	if resA2.Masked != resA.Masked {
		t.Errorf("A's record was overwritten by B's rejected attempt: %q vs %q", resA2.Masked, resA.Masked)
	}
}

// TestLegacyRecordOnlyAccessibleToDefaultSystem verifies that a record with
// no recorded owner (as decoded from data written before ownership tracking
// existed) is accessible only to the configured default system, not to an
// arbitrary other system.
func TestLegacyRecordOnlyAccessibleToDefaultSystem(t *testing.T) {
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
	strategies := map[string]mask.Strategy{"partial": mask.MustPartial()}
	e := New(p, st, strategies)
	ctx := context.Background()

	// Simulate a legacy record: SystemID left at its zero value.
	legacyOpt := Options{Strategy: "partial", TTL: time.Minute, SystemID: ""}
	if _, err := e.MaskEx(ctx, "legacy", testText, legacyOpt); err != nil {
		t.Fatalf("seed legacy record: %v", err)
	}

	// An arbitrary other system must not be able to read it via /unmask.
	otherOpt := Options{SystemID: "someOtherSystem", DefaultSystemID: "checker"}
	if _, _, err := e.Unmask(ctx, "legacy", testText, otherOpt); !isNotFound(err) {
		t.Errorf("expected ErrNotFound for a non-default system, got %v", err)
	}

	// The configured default system may still access it.
	defaultOpt := Options{Strategy: "partial", TTL: time.Minute, Unmask: true, SystemID: "checker", DefaultSystemID: "checker"}
	res, err := e.Process(ctx, "legacy", testText, defaultOpt)
	if err != nil {
		t.Fatalf("Process as default system: %v", err)
	}
	if res.Result == testText {
		t.Errorf("default system should receive the stored mask, not the original")
	}
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

func isForeignRecord(err error) bool {
	return err != nil && strings.Contains(err.Error(), "another system")
}
