package mask

import (
	"fmt"
	"math/rand"
	"testing"

	"pdn-shield/internal/pii"
)

// TestRestoreDuplicateStartAcrossMessages reproduces the scenario that used to
// panic: MaskBatchEx (via chat) records two Replacements from two different
// messages that share the same masked token (because DocState dedupes equal
// values), each with a local Start of 0. When the LLM response happens to
// start with that exact token, the recorded position for the second
// replacement is genuinely valid (masked[0:len] == Masked) but 0 is before
// pos (already consumed by the first replacement's match). Restore must fall
// back to searching instead of panicking on a negative slice.
func TestRestoreDuplicateStartAcrossMessages(t *testing.T) {
	reps := []Replacement{
		{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "[PHONE_1]", Start: 0, End: len("[PHONE_1]")},
		{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "[PHONE_1]", Start: 0, End: len("[PHONE_1]")},
	}
	// The model repeated the token only once, even though it was recorded
	// twice (once per message).
	masked := "[PHONE_1] is your number, thanks."
	restored, misses := Restore(masked, reps)
	if misses != 1 {
		t.Errorf("misses = %d, want 1 (only one occurrence in the response)", misses)
	}
	want := "+7 (916) 123-45-67 is your number, thanks."
	if restored != want {
		t.Errorf("restored = %q, want %q", restored, want)
	}
}

// TestRestoreSameTokenRepeatedTwice verifies that when the model *does* repeat
// the shared token twice, both occurrences are restored in order with zero
// misses.
func TestRestoreSameTokenRepeatedTwice(t *testing.T) {
	reps := []Replacement{
		{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "[PHONE_1]", Start: 0, End: 9},
		{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "[PHONE_1]", Start: 0, End: 9},
	}
	masked := "Call [PHONE_1] or [PHONE_1] again."
	restored, misses := Restore(masked, reps)
	if misses != 0 {
		t.Errorf("misses = %d, want 0", misses)
	}
	want := "Call +7 (916) 123-45-67 or +7 (916) 123-45-67 again."
	if restored != want {
		t.Errorf("restored = %q, want %q", restored, want)
	}
}

// TestRestoreMissingTokens verifies that a replacement whose token never
// appears in the masked text is reported as a miss, without affecting the
// restoration of the other replacements.
func TestRestoreMissingTokens(t *testing.T) {
	reps := []Replacement{
		{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "[PHONE_1]", Start: 0, End: 9},
		{Category: pii.CatEmail, Original: "ivan@mail.ru", Masked: "[EMAIL_1]", Start: 20, End: 29},
	}
	// [EMAIL_1] was dropped entirely by the model.
	masked := "Call [PHONE_1] please."
	restored, misses := Restore(masked, reps)
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	if restored != "Call +7 (916) 123-45-67 please." {
		t.Errorf("restored = %q", restored)
	}
}

// TestRestorePermutedFragments verifies replacements are restored correctly
// even when the model reordered the fragments relative to their recorded
// Start order.
func TestRestorePermutedFragments(t *testing.T) {
	reps := []Replacement{
		{Category: pii.CatFullName, Original: "Иванов", Masked: "[NAME_1]", Start: 0, End: 8},
		{Category: pii.CatPhone, Original: "+7 916", Masked: "[PHONE_1]", Start: 20, End: 29},
	}
	// The model put the phone token before the name token, unlike the
	// recorded order.
	masked := "[PHONE_1] belongs to [NAME_1]."
	restored, misses := Restore(masked, reps)
	if misses != 0 {
		t.Errorf("misses = %d, want 0", misses)
	}
	if restored != "+7 916 belongs to Иванов." {
		t.Errorf("restored = %q", restored)
	}
}

// TestRestoreInvalidRecordedPositions verifies Restore never panics and
// always returns a result when Start/End are nonsensical (out of range,
// inverted, or referring past the end of the masked text).
func TestRestoreInvalidRecordedPositions(t *testing.T) {
	masked := "short"
	cases := []Replacement{
		{Masked: "x", Original: "y", Start: -5, End: -1},
		{Masked: "x", Original: "y", Start: 100, End: 200},
		{Masked: "x", Original: "y", Start: 3, End: 1},
		{Masked: "x", Original: "y", Start: 0, End: 1000},
		{Masked: "", Original: "y", Start: 0, End: 0},
	}
	for i, r := range cases {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("case %d panicked: %v", i, rec)
				}
			}()
			Restore(masked, []Replacement{r})
		}()
	}
}

// TestRestoreFuzzNeverPanics generates many masked strings and replacement
// sets with random, possibly-inconsistent Start/End offsets and asserts
// Restore never panics, regardless of input.
func TestRestoreFuzzNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alphabet := "abc[]_123 XYZмасктокен"
	for iter := 0; iter < 500; iter++ {
		masked := randString(rng, alphabet, rng.Intn(40))
		n := rng.Intn(5)
		reps := make([]Replacement, n)
		for i := 0; i < n; i++ {
			reps[i] = Replacement{
				Category: pii.CatPhone,
				Original: fmt.Sprintf("ORIG_%d", i),
				Masked:   randString(rng, alphabet, rng.Intn(10)),
				Start:    rng.Intn(60) - 10,
				End:      rng.Intn(60) - 10,
			}
		}
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("iter %d panicked with masked=%q reps=%+v: %v", iter, masked, reps, rec)
				}
			}()
			Restore(masked, reps)
		}()
	}
}

func randString(rng *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}
