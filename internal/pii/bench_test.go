package pii_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
)

// shortText is a realistic ~120-byte document exercising every category.
const shortText = "Иван Петров, дата рождения 12.05.1990, гражданство РФ. Паспорт 4509 123456 выдан 05.12.1990, код подразделения 770-001. Email ivan.petrov@example.com, телефон +7 (916) 123-45-67."

// longText is a ~50 KiB document built by repeating the dataset.
var longText = buildLongText()

func buildLongText() string {
	f, err := os.Open("testdata/dataset.jsonl")
	if err != nil {
		return shortText
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Extract the "text" field value.
		start := strings.Index(line, `"text":"`)
		if start < 0 {
			continue
		}
		start += len(`"text":"`)
		end := strings.Index(line[start:], `"`)
		if end < 0 {
			continue
		}
		b.WriteString(line[start : start+end])
		b.WriteString(" ")
		if b.Len() >= 50*1024 {
			break
		}
	}
	return b.String()
}

func benchPipeline(b *testing.B, text string) {
	p := pii.NewPipeline(detectors.Default()...)
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Run(text)
	}
}

// BenchmarkPipelineShort measures a single ~120-byte document.
//
// Before (baseline): 1.40 ms/op, 1653 allocs/op.
// After:             0.20 ms/op,   95 allocs/op.
func BenchmarkPipelineShort(b *testing.B) {
	benchPipeline(b, shortText)
}

// BenchmarkPipelineLong measures a ~50 KiB document.
//
// Before (baseline): 56.2 ms/op, 5637 allocs/op.
// After:             11.4 ms/op, 2325 allocs/op.
func BenchmarkPipelineLong(b *testing.B) {
	benchPipeline(b, longText)
}
