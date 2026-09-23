package mask

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"pdn-shield/internal/pii"
)

func TestApplyRestoreRoundTrip(t *testing.T) {
	strategies := []Strategy{MustPartial(), NewFull(), NewToken(), NewSynthetic()}
	for _, s := range strategies {
		t.Run(s.Name(), func(t *testing.T) {
			text := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67, email ivan@mail.ru, карта 4111 1111 1111 1111, cvv 123"
			spans := []pii.Span{
				{Start: 7, End: 30, Category: pii.CatFullName},
				{Start: 40, End: 51, Category: pii.CatPassport},
				{Start: 57, End: 74, Category: pii.CatPhone},
				{Start: 81, End: 94, Category: pii.CatEmail},
				{Start: 101, End: 118, Category: pii.CatCardNumber},
				{Start: 125, End: 128, Category: pii.CatCVV},
			}
			doc := NewDocState()
			masked, reps := Apply(text, spans, s, doc)
			restored, misses := Restore(masked, reps)
			if misses != 0 {
				t.Errorf("Restore reported %d misses", misses)
			}
			if restored != text {
				t.Errorf("round-trip failed:\n got %q\nwant %q", restored, text)
			}
		})
	}
}

func TestRestoreWithShift(t *testing.T) {
	s := MustPartial()
	text := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67"
	spans := []pii.Span{
		{Start: 7, End: 30, Category: pii.CatFullName},
		{Start: 40, End: 51, Category: pii.CatPassport},
		{Start: 57, End: 74, Category: pii.CatPhone},
	}
	doc := NewDocState()
	masked, reps := Apply(text, spans, s, doc)
	// Insert a word at the beginning, shifting all offsets.
	shifted := "ВНИМАНИЕ " + masked
	restored, misses := Restore(shifted, reps)
	if misses != 0 {
		t.Errorf("Restore with shift reported %d misses", misses)
	}
	if restored != "ВНИМАНИЕ "+text {
		t.Errorf("shifted restore failed:\n got %q\nwant %q", restored, "ВНИМАНИЕ "+text)
	}
}

// datasetRecord mirrors the dataset.jsonl schema for round-trip testing.
type datasetRecord struct {
	ID    string        `json:"id"`
	Text  string        `json:"text"`
	Spans []datasetSpan `json:"spans"`
}

type datasetSpan struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Value    string `json:"value"`
	Category string `json:"category"`
}

func loadDatasetFileForMask(t *testing.T, path string) []datasetRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dataset: %v", err)
	}
	defer f.Close()
	var records []datasetRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec datasetRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		resolveSpanOffsets(t, &rec)
		records = append(records, rec)
	}
	return records
}

// resolveSpanOffsets fills in the start/end offsets of spans whose value is
// present, locating the value within the record text.
func resolveSpanOffsets(t *testing.T, rec *datasetRecord) {
	t.Helper()
	for i := range rec.Spans {
		sp := &rec.Spans[i]
		if sp.Value == "" {
			continue
		}
		idx := strings.Index(rec.Text, sp.Value)
		if idx < 0 {
			t.Fatalf("%s: value %q not found", rec.ID, sp.Value)
		}
		sp.Start = idx
		sp.End = idx + len(sp.Value)
	}
}

func TestRestoreRoundTripDataset(t *testing.T) {
	records := loadDatasetFileForMask(t, "../pii/testdata/dataset.jsonl")
	runRoundTrip(t, records)
}

func TestRestoreRoundTripBlind(t *testing.T) {
	records := loadDatasetFileForMask(t, "../pii/testdata/blind.jsonl")
	runRoundTrip(t, records)
}

// runRoundTrip verifies that every strategy restores the original text from the
// masked text for every record.
func runRoundTrip(t *testing.T, records []datasetRecord) {
	t.Helper()
	strategies := []Strategy{MustPartial(), NewFull(), NewToken(), NewSynthetic()}
	for _, s := range strategies {
		t.Run(s.Name(), func(t *testing.T) {
			for _, rec := range records {
				if len(rec.Spans) == 0 {
					continue
				}
				checkRoundTrip(t, s, rec)
			}
		})
	}
}

// checkRoundTrip verifies that strategy s restores rec.Text from the masked text.
func checkRoundTrip(t *testing.T, s Strategy, rec datasetRecord) {
	t.Helper()
	spans := make([]pii.Span, 0, len(rec.Spans))
	for _, sp := range rec.Spans {
		spans = append(spans, pii.Span{
			Start:    sp.Start,
			End:      sp.End,
			Category: pii.Category(sp.Category),
		})
	}
	doc := NewDocState()
	masked, reps := Apply(rec.Text, spans, s, doc)
	restored, misses := Restore(masked, reps)
	if misses != 0 {
		t.Errorf("%s (%s): Restore reported %d misses", rec.ID, s.Name(), misses)
	}
	if restored != rec.Text {
		t.Errorf("%s (%s): round-trip failed:\n got %q\nwant %q", rec.ID, s.Name(), restored, rec.Text)
	}
}

// TestFullStrategy verifies the exact masking expectations for the full
// strategy.
func TestFullStrategy(t *testing.T) {
	s := NewFull()
	doc := NewDocState()
	cases := []struct {
		cat   pii.Category
		value string
		want  string
	}{
		{pii.CatFullName, "Иванов Иван Иванович", "****** **** ********"},
		{pii.CatPassport, "4509 123456", "**** ******"},
		{pii.CatPhone, "+7 (916) 123-45-67", "+* (***) ***-**-**"},
		{pii.CatEmail, "ivan@mail.ru", "****@****.**"},
		{pii.CatBirthDate, "12 мая 1990 года", "** *** **** года"},
		{pii.CatAddress, "г. Казани", "г. ******"},
		{pii.CatAddress, "ул. Ленина, д. 5, кв. 12", "ул. ******, д. *, кв. **"},
		{pii.CatPassportIssuer, "ОУФМС России по г. Москве", "***** ****** по г. ******"},
		{pii.CatPassport, "серия 4509 номер 123456", "серия **** номер ******"},
		{pii.CatCitizenship, "РФ", "**"},
		{pii.CatCitizenship, "Российская Федерация", "********** *********"},
	}
	for _, tc := range cases {
		got := s.Mask(tc.value, tc.cat, doc)
		if got != tc.want {
			t.Errorf("Mask(%q, %s) = %q, want %q", tc.value, tc.cat, got, tc.want)
		}
	}
}
