package pii_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
)

// datasetRecord is one line of dataset.jsonl.
type datasetRecord struct {
	ID    string        `json:"id"`
	Text  string        `json:"text"`
	Spans []datasetSpan `json:"spans"`
}

// datasetSpan is an expected span. Either Start/End (byte offsets) or Value
// (the test locates the first occurrence) must be provided.
type datasetSpan struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Value    string `json:"value"`
	Category string `json:"category"`
}

// loadDataset reads and parses dataset.jsonl, resolving Value-based spans into
// byte offsets.
func loadDataset(t *testing.T) []datasetRecord {
	return loadDatasetFile(t, "testdata/dataset.jsonl")
}

// loadDatasetFile reads and parses a JSONL dataset file, resolving Value-based
// spans into byte offsets.
func loadDatasetFile(t *testing.T, path string) []datasetRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dataset: %v", err)
	}
	defer f.Close()

	var records []datasetRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec datasetRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", line, err)
		}
		resolveValueSpans(t, line, &rec)
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan dataset: %v", err)
	}
	return records
}

// resolveValueSpans resolves Value-based spans into byte offsets, failing when a
// value is missing or occurs more than once.
func resolveValueSpans(t *testing.T, line int, rec *datasetRecord) {
	t.Helper()
	for i := range rec.Spans {
		sp := &rec.Spans[i]
		if sp.Value == "" {
			continue
		}
		idx := strings.Index(rec.Text, sp.Value)
		if idx < 0 {
			t.Fatalf("line %d (%s): value %q not found in text %q", line, rec.ID, sp.Value, rec.Text)
		}
		if strings.Contains(rec.Text[idx+len(sp.Value):], sp.Value) {
			t.Fatalf("line %d (%s): value %q occurs more than once in text %q", line, rec.ID, sp.Value, rec.Text)
		}
		sp.Start = idx
		sp.End = idx + len(sp.Value)
	}
}

// TestDatasetSpansAreClean verifies that every expected span trims a non-empty
// string with no leading/trailing spaces or commas.
func TestDatasetSpansAreClean(t *testing.T) {
	for _, rec := range loadDataset(t) {
		for _, sp := range rec.Spans {
			checkCleanSpan(t, rec, sp)
		}
	}
}

// checkCleanSpan verifies that one expected span is valid and trims a non-empty
// string with no leading/trailing spaces or commas.
func checkCleanSpan(t *testing.T, rec datasetRecord, sp datasetSpan) {
	t.Helper()
	if sp.Start < 0 || sp.End > len(rec.Text) || sp.Start >= sp.End {
		t.Errorf("%s: invalid span [%d:%d] in %q", rec.ID, sp.Start, sp.End, rec.Text)
		return
	}
	val := rec.Text[sp.Start:sp.End]
	if strings.TrimSpace(val) == "" {
		t.Errorf("%s: span [%d:%d] is empty/whitespace in %q", rec.ID, sp.Start, sp.End, rec.Text)
	}
	if strings.TrimSpace(val) != val {
		t.Errorf("%s: span %q has leading/trailing whitespace in %q", rec.ID, val, rec.Text)
	}
	if strings.HasPrefix(val, ",") || strings.HasSuffix(val, ",") {
		t.Errorf("%s: span %q has leading/trailing comma in %q", rec.ID, val, rec.Text)
	}
}

// overlapRatio returns the fraction of the expected span covered by the
// detected span.
func overlapRatio(det, exp datasetSpan) float64 {
	overlap := 0
	if det.Start < exp.End && exp.Start < det.End {
		lo := det.Start
		if exp.Start > lo {
			lo = exp.Start
		}
		hi := det.End
		if exp.End < hi {
			hi = exp.End
		}
		overlap = hi - lo
	}
	expLen := exp.End - exp.Start
	if expLen == 0 {
		return 0
	}
	return float64(overlap) / float64(expLen)
}

// matchRatio reports how well a detected span matches an expected span. It is
// the larger of the overlap relative to the expected span and the overlap
// relative to the detected span. This tolerates convention differences where
// our spans exclude context words that the external markup includes (e.g.
// "серия: 4765, номер: 549251" vs our "4765, номер: 549251").
func matchRatio(det, exp datasetSpan) float64 {
	r1 := overlapRatio(det, exp)
	r2 := overlapRatio(exp, det)
	if r2 > r1 {
		return r2
	}
	return r1
}

// strictMatch reports whether a detected span matches an expected span under
// the strict rule: same category and at least 80% overlap in both directions
// (relative to the expected span and relative to the detected span).
func strictMatch(det, exp datasetSpan) bool {
	return overlapRatio(det, exp) >= 0.8 && overlapRatio(exp, det) >= 0.8
}

// softMatch reports whether a detected span matches an expected span under the
// soft rule: same category and matchRatio at least 0.8. It tolerates convention
// differences where our spans exclude context words that the external markup
// includes.
func softMatch(det, exp datasetSpan) bool {
	return matchRatio(det, exp) >= 0.8
}

// TestAccuracy runs the pipeline over the dataset and reports precision/recall
// per category using strict span matching.
func TestAccuracy(t *testing.T) {
	records := loadDataset(t)
	runAccuracy(t, "dataset", records, 0.95, strictMatch)
}

// TestAccuracyBlind runs the pipeline over the blind dataset, which the
// detectors have not been tuned on, and enforces the same precision/recall
// threshold using strict span matching.
func TestAccuracyBlind(t *testing.T) {
	records := loadDatasetFile(t, "testdata/blind.jsonl")
	runAccuracy(t, "blind", records, 0.95, strictMatch)
}

// TestAccuracyExternal runs the pipeline over a dataset given by the
// PDN_EVAL_DATASET environment variable. It is skipped when the variable is
// empty and only reports metrics without enforcing a threshold. It prints both
// a strict table and a soft table (with the markup-convention allowance).
func TestAccuracyExternal(t *testing.T) {
	path := os.Getenv("PDN_EVAL_DATASET")
	if path == "" {
		t.Skip("PDN_EVAL_DATASET not set")
	}
	records := loadDatasetFile(t, path)
	runAccuracy(t, "external (strict)", records, 0.0, strictMatch)
	runAccuracy(
		t,
		"external (soft, с поправкой на конвенцию разметки: контекстные слова вне спана)",
		records,
		0.0,
		softMatch,
	)
}

// matchFunc decides whether a detected span matches an expected span.
type matchFunc func(det, exp datasetSpan) bool

// runAccuracy runs the pipeline over records, prints a per-category table and
// enforces an overall precision/recall threshold. A threshold of 0 disables the
// check.
// stats holds the true-positive/false-positive/false-negative counts for one
// category.
type stats struct {
	tp, fp, fn int
}

func runAccuracy(t *testing.T, name string, records []datasetRecord, threshold float64, match matchFunc) {
	t.Helper()
	p := pii.NewPipeline(detectors.Default()...)

	byCat := make(map[pii.Category]*stats)
	var totalTP, totalFP, totalFN int

	for _, rec := range records {
		accumulateRecord(p, rec, byCat, match, &totalTP, &totalFP, &totalFN)
	}

	printAccuracyTable(name, byCat, totalTP, totalFP, totalFN)

	if threshold > 0 {
		precision := ratio(totalTP, totalTP+totalFP)
		recall := ratio(totalTP, totalTP+totalFN)
		if recall < threshold {
			t.Errorf("overall recall %.3f < %.3f", recall, threshold)
		}
		if precision < threshold {
			t.Errorf("overall precision %.3f < %.3f", precision, threshold)
		}
	}
}

// ratio returns a/b as a float, or 0 when b is 0.
func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// printAccuracyTable prints the per-category and total precision/recall/f1 table.
func printAccuracyTable(name string, byCat map[pii.Category]*stats, totalTP, totalFP, totalFN int) {
	fmt.Printf("\n=== Accuracy by category (%s) ===", name)
	fmt.Println()
	fmt.Printf("%-18s %6s %6s %6s %8s %8s %8s\n", "category", "tp", "fp", "fn", "precision", "recall", "f1")
	for _, cat := range []pii.Category{
		pii.CatPhone, pii.CatEmail, pii.CatINN, pii.CatCardNumber, pii.CatCVV, pii.CatPIN, pii.CatPassport,
		pii.CatDivisionCode, pii.CatDriverLicense, pii.CatSNILS, pii.CatForeignPassport,
		pii.CatBirthDate, pii.CatPassportDate, pii.CatDate, pii.CatCitizenship,
		pii.CatFullName, pii.CatCardHolder, pii.CatAddress, pii.CatBirthPlace, pii.CatPassportIssuer,
	} {
		s := byCat[cat]
		if s == nil {
			s = &stats{}
		}
		precision := ratio(s.tp, s.tp+s.fp)
		recall := ratio(s.tp, s.tp+s.fn)
		f1 := f1Score(precision, recall)
		fmt.Printf("%-18s %6d %6d %6d %8.3f %8.3f %8.3f\n", cat, s.tp, s.fp, s.fn, precision, recall, f1)
	}

	precision := ratio(totalTP, totalTP+totalFP)
	recall := ratio(totalTP, totalTP+totalFN)
	f1 := f1Score(precision, recall)
	fmt.Printf("\n%-18s %6d %6d %6d %8.3f %8.3f %8.3f\n", "TOTAL", totalTP, totalFP, totalFN, precision, recall, f1)
}

// f1Score returns the harmonic mean of precision and recall, or 0 when both are 0.
func f1Score(precision, recall float64) float64 {
	if precision+recall == 0 {
		return 0
	}
	return 2 * precision * recall / (precision + recall)
}

// bestMatch returns the index of the expected span that best overlaps a
// detected span, or -1 when no expected span shares the detected category.
func bestMatch(expected []datasetSpan, det pii.Span) int {
	best := -1
	bestRatio := 0.0
	for i, exp := range expected {
		if exp.Category != string(det.Category) {
			continue
		}
		r := matchRatio(datasetSpan{Start: det.Start, End: det.End}, exp)
		if r > bestRatio {
			bestRatio = r
			best = i
		}
	}
	return best
}

// accumulateRecord runs the pipeline over one record and updates the per-category
// and total true-positive/false-positive/false-negative counters.
func accumulateRecord(
	p *pii.Pipeline,
	rec datasetRecord,
	byCat map[pii.Category]*stats,
	match matchFunc,
	totalTP, totalFP, totalFN *int,
) {
	res := p.Run(rec.Text)
	matched := make([]bool, len(rec.Spans))
	for _, det := range res.Spans {
		recordDetected(det, rec, byCat, match, matched, totalTP, totalFP)
	}
	for i, exp := range rec.Spans {
		recordMissed(i, exp, byCat, matched, totalFN)
	}
}

// recordDetected updates the counters for one detected span.
func recordDetected(
	det pii.Span,
	rec datasetRecord,
	byCat map[pii.Category]*stats,
	match matchFunc,
	matched []bool,
	totalTP, totalFP *int,
) {
	cat := det.Category
	st := ensureStats(byCat, cat)
	best := bestMatch(rec.Spans, det)
	if best >= 0 && match(datasetSpan{Start: det.Start, End: det.End}, rec.Spans[best]) {
		if !matched[best] {
			matched[best] = true
			st.tp++
			*totalTP++
		}
		return
	}
	st.fp++
	*totalFP++
}

// recordMissed updates the false-negative counters for an unmatched expected span.
func recordMissed(i int, exp datasetSpan, byCat map[pii.Category]*stats, matched []bool, totalFN *int) {
	if matched[i] {
		return
	}
	ensureStats(byCat, pii.Category(exp.Category)).fn++
	*totalFN++
}

// ensureStats returns the stats for a category, creating it when absent.
func ensureStats(byCat map[pii.Category]*stats, cat pii.Category) *stats {
	if byCat[cat] == nil {
		byCat[cat] = &stats{}
	}
	return byCat[cat]
}
