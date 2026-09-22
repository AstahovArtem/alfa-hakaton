// Package mask turns detected PII spans into masked text and can restore the
// original text from the masked text and the recorded replacements.
package mask

import (
	"sort"
	"strings"

	"pdn-shield/internal/pii"
)

// Strategy turns a detected span into its masked replacement.
type Strategy interface {
	Name() string
	// Mask returns the replacement for value. cat gives the category and doc a
	// per-document counter/lookup so the same value gets the same replacement
	// within one document.
	Mask(value string, cat pii.Category, doc *DocState) string
}

// DocState is per-document state: value -> replacement memo and counters per
// category.
type DocState struct {
	memo map[string]string
	seq  map[pii.Category]int
}

// NewDocState creates an empty DocState.
func NewDocState() *DocState {
	return &DocState{
		memo: make(map[string]string),
		seq:  make(map[pii.Category]int),
	}
}

// Memo returns the previously recorded replacement for value, or "" if none.
func (d *DocState) Memo(value string) string {
	return d.memo[value]
}

// Remember records the replacement for value.
func (d *DocState) Remember(value, replacement string) {
	d.memo[value] = replacement
}

// Next returns the next sequence number for a category.
func (d *DocState) Next(cat pii.Category) int {
	d.seq[cat]++
	return d.seq[cat]
}

// Replacement records one substitution in the masked text.
type Replacement struct {
	Category pii.Category `json:"c"`
	Original string       `json:"o"`
	Masked   string       `json:"m"`
	Start    int          `json:"s"` // byte offset of Masked in the masked text
	End      int          `json:"e"`
}

// Apply masks text using spans and strategy; returns masked text and
// replacements (sorted by Start, offsets refer to the MASKED text).
func Apply(text string, spans []pii.Span, s Strategy, doc *DocState) (string, []Replacement) {
	if doc == nil {
		doc = NewDocState()
	}
	sorted := make([]pii.Span, len(spans))
	copy(sorted, spans)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End > sorted[j].End
	})

	var b strings.Builder
	var reps []Replacement
	pos := 0
	for _, sp := range sorted {
		if sp.Start < pos {
			continue
		}
		if sp.Start > len(text) || sp.End > len(text) || sp.Start >= sp.End {
			continue
		}
		value := text[sp.Start:sp.End]
		replacement := s.Mask(value, sp.Category, doc)
		b.WriteString(text[pos:sp.Start])
		start := b.Len()
		b.WriteString(replacement)
		end := b.Len()
		reps = append(reps, Replacement{
			Category: sp.Category,
			Original: value,
			Masked:   replacement,
			Start:    start,
			End:      end,
		})
		pos = sp.End
	}
	b.WriteString(text[pos:])
	return b.String(), reps
}

// Restore rebuilds the original text from masked text and replacements.
// For each replacement in order, if masked[Start:End] == Masked the recorded
// positions are used; otherwise Masked is searched in the masked text starting
// after the previous replacement (the LLM or a proxy may have shifted the
// text). Unfound replacements are skipped and reported in the returned count
// of misses.
func Restore(masked string, reps []Replacement) (string, int) {
	sorted := make([]Replacement, len(reps))
	copy(sorted, reps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start < sorted[j].Start
	})

	var b strings.Builder
	misses := 0
	searchFrom := 0
	pos := 0
	for _, r := range sorted {
		// Try the recorded position first.
		start, end := r.Start, r.End
		if start < 0 || end > len(masked) || start > end || masked[start:end] != r.Masked {
			// Fall back to searching after the previous replacement.
			idx := strings.Index(masked[searchFrom:], r.Masked)
			if idx < 0 {
				misses++
				continue
			}
			start = searchFrom + idx
			end = start + len(r.Masked)
		}
		b.WriteString(masked[pos:start])
		b.WriteString(r.Original)
		pos = end
		searchFrom = end
	}
	b.WriteString(masked[pos:])
	return b.String(), misses
}
