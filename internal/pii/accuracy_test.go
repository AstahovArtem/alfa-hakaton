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
	t.Helper()
	f, err := os.Open("testdata/dataset.jsonl")
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
		for i := range rec.Spans {
			sp := &rec.Spans[i]
			if sp.Value != "" {
				idx := strings.Index(rec.Text, sp.Value)
				if idx < 0 {
					t.Fatalf("line %d (%s): value %q not found in text %q", line, rec.ID, sp.Value, rec.Text)
				}
				if strings.Index(rec.Text[idx+len(sp.Value):], sp.Value) >= 0 {
					t.Fatalf("line %d (%s): value %q occurs more than once in text %q", line, rec.ID, sp.Value, rec.Text)
				}
				sp.Start = idx
				sp.End = idx + len(sp.Value)
			}
		}
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan dataset: %v", err)
	}
	return records
}

// TestDatasetSpansAreClean verifies that every expected span trims a non-empty
// string with no leading/trailing spaces or commas.
func TestDatasetSpansAreClean(t *testing.T) {
	for _, rec := range loadDataset(t) {
		for _, sp := range rec.Spans {
			if sp.Start < 0 || sp.End > len(rec.Text) || sp.Start >= sp.End {
				t.Errorf("%s: invalid span [%d:%d] in %q", rec.ID, sp.Start, sp.End, rec.Text)
				continue
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

// TestAccuracy runs the pipeline over the dataset and reports precision/recall
// per category.
func TestAccuracy(t *testing.T) {
	records := loadDataset(t)
	p := pii.NewPipeline(detectors.Default()...)

	type stats struct {
		tp, fp, fn int
	}
	byCat := make(map[pii.Category]*stats)
	var totalTP, totalFP, totalFN int

	for _, rec := range records {
		res := p.Run(rec.Text)
		matched := make([]bool, len(rec.Spans))
		for _, det := range res.Spans {
			cat := det.Category
			if byCat[cat] == nil {
				byCat[cat] = &stats{}
			}
			best := -1
			bestRatio := 0.0
			for i, exp := range rec.Spans {
				if exp.Category != string(cat) {
					continue
				}
				r := overlapRatio(datasetSpan{Start: det.Start, End: det.End}, exp)
				if r > bestRatio {
					bestRatio = r
					best = i
				}
			}
			if best >= 0 && bestRatio >= 0.8 {
				if !matched[best] {
					matched[best] = true
					byCat[cat].tp++
					totalTP++
				}
			} else {
				byCat[cat].fp++
				totalFP++
			}
		}
		for i, exp := range rec.Spans {
			if matched[i] {
				continue
			}
			cat := pii.Category(exp.Category)
			if byCat[cat] == nil {
				byCat[cat] = &stats{}
			}
			byCat[cat].fn++
			totalFN++
		}
	}

	fmt.Println("\n=== Accuracy by category ===")
	fmt.Printf("%-18s %6s %6s %6s %8s %8s %8s\n", "category", "tp", "fp", "fn", "precision", "recall", "f1")
	for _, cat := range []pii.Category{
		pii.CatPhone, pii.CatEmail, pii.CatINN, pii.CatCardNumber, pii.CatCVV, pii.CatPIN, pii.CatPassport,
		pii.CatDivisionCode, pii.CatDriverLicense, pii.CatSNILS, pii.CatForeignPassport,
		pii.CatBirthDate, pii.CatPassportDate, pii.CatDate, pii.CatCitizenship,
	} {
		s := byCat[cat]
		if s == nil {
			s = &stats{}
		}
		precision := 0.0
		if s.tp+s.fp > 0 {
			precision = float64(s.tp) / float64(s.tp+s.fp)
		}
		recall := 0.0
		if s.tp+s.fn > 0 {
			recall = float64(s.tp) / float64(s.tp+s.fn)
		}
		f1 := 0.0
		if precision+recall > 0 {
			f1 = 2 * precision * recall / (precision + recall)
		}
		fmt.Printf("%-18s %6d %6d %6d %8.3f %8.3f %8.3f\n", cat, s.tp, s.fp, s.fn, precision, recall, f1)
	}

	precision := 0.0
	if totalTP+totalFP > 0 {
		precision = float64(totalTP) / float64(totalTP+totalFP)
	}
	recall := 0.0
	if totalTP+totalFN > 0 {
		recall = float64(totalTP) / float64(totalTP+totalFN)
	}
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	fmt.Printf("\n%-18s %6d %6d %6d %8.3f %8.3f %8.3f\n", "TOTAL", totalTP, totalFP, totalFN, precision, recall, f1)

	if recall < 0.95 {
		t.Errorf("overall recall %.3f < 0.95", recall)
	}
	if precision < 0.95 {
		t.Errorf("overall precision %.3f < 0.95", precision)
	}
}
