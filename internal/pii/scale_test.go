package pii_test

import (
	"strings"
	"testing"
	"time"

	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
)

// scaleParagraph is a realistic document exercising the expensive detectors
// (names, passport, phone, address, date, issuing authority). It is repeated to
// build texts of increasing size so the pipeline's scaling can be measured.
const scaleParagraph = "Иван Петров, дата рождения 12.05.1990, гражданство РФ. " +
	"Паспорт 4509 123456 выдан 05.12.1990, код подразделения 770-001. " +
	"Адрес: г. Казань, ул. Кремлёвская 5, кв. 15. " +
	"Телефон +7 (916) 123-45-67, email ivan.petrov@example.com. " +
	"Орган выдачи: Отделом по вопросам миграции ОМВД России по г. Казани. "

// buildScaleText returns a text of approximately size bytes built by repeating
// the scale paragraph.
func buildScaleText(size int) string {
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(scaleParagraph)
	}
	return b.String()
}

// TestScaleLinear verifies that the pipeline scales linearly with text size. A
// 256 KB text must be processed in no more than 1.5 s, and the ratio of the
// 256 KB time to the 64 KB time must be no more than 6 (linear with headroom).
func TestScaleLinear(t *testing.T) {
	p := pii.NewPipeline(detectors.Default()...)
	sizes := []int{4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024}
	times := make([]time.Duration, len(sizes))

	for i, size := range sizes {
		text := buildScaleText(size)
		start := time.Now()
		p.Run(text)
		times[i] = time.Since(start)
		t.Logf("%7d bytes  %10.1f ms", size, float64(times[i])/float64(time.Millisecond))
	}

	// 256 KB must be processed within 1.5 s. Under the race detector the
	// pipeline runs far slower, so the absolute bound is relaxed there while the
	// linear-scaling ratio below is still enforced.
	limit := 1500 * time.Millisecond
	if raceEnabled {
		limit = 30 * time.Second
	}
	if times[3] > limit {
		t.Errorf("256 KB processed in %v, want <= %v", times[3], limit)
	}

	// The 256 KB / 64 KB time ratio must be <= 6 (linear with headroom).
	ratio := float64(times[3]) / float64(times[2])
	if ratio > 6 {
		t.Errorf("256 KB / 64 KB time ratio %.2f, want <= 6", ratio)
	}
}
