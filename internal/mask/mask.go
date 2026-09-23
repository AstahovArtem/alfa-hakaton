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

// claim is a resolved [start,end) range in the masked text that one
// replacement occupies, together with the original value to splice in.
type claim struct {
	start, end int
	original   string
}

// Restore rebuilds the original text from masked text and replacements. It
// does not assume the replacements appear in the masked text in their
// recorded Start order: an LLM or a proxy may duplicate, drop, shift or
// reorder fragments. Instead it resolves, for every replacement, the actual
// [start,end) range it occupies in masked (its recorded position when that
// is still valid and unclaimed, otherwise the next unclaimed occurrence of
// its Masked text), then splices the original values in at the order they
// actually occur. Every slice bound is checked before use, so a corrupted or
// replayed record can never panic here. Replacements that cannot be resolved
// are skipped and reported in the returned count of misses.
func Restore(masked string, reps []Replacement) (string, int) {
	sorted := make([]Replacement, len(reps))
	copy(sorted, reps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start < sorted[j].Start
	})

	var claims []claim
	misses := 0

	// Phase 1: trust each replacement's recorded position when it is
	// in-bounds, matches Masked exactly and does not overlap a range already
	// claimed by an earlier (lower Start) replacement.
	var unresolved []Replacement
	for _, r := range sorted {
		if inBounds(masked, r.Start, r.End) && masked[r.Start:r.End] == r.Masked && !overlapsAny(claims, r.Start, r.End) {
			claims = append(claims, claim{r.Start, r.End, r.Original})
			continue
		}
		unresolved = append(unresolved, r)
	}

	// Phase 2: for everything left (stale, duplicated or reordered
	// positions), search the whole text for the next unclaimed occurrence of
	// Masked.
	for _, r := range unresolved {
		start, end, ok := findUnclaimed(masked, r.Masked, claims)
		if !ok {
			misses++
			continue
		}
		claims = append(claims, claim{start, end, r.Original})
	}

	// Build the output in the order the claims actually occur in masked, not
	// the order the replacements were recorded in.
	sort.Slice(claims, func(i, j int) bool {
		return claims[i].start < claims[j].start
	})
	var b strings.Builder
	pos := 0
	for _, c := range claims {
		if c.start < pos || !inBounds(masked, c.start, c.end) {
			// Defensive: phase 1/2 should never produce an overlapping or
			// out-of-range claim, but never slice on an unchecked value.
			misses++
			continue
		}
		b.WriteString(masked[pos:c.start])
		b.WriteString(c.original)
		pos = c.end
	}
	b.WriteString(masked[pos:])
	return b.String(), misses
}

// inBounds reports whether [start,end) is a legal, non-empty-or-not slice
// bound of masked.
func inBounds(masked string, start, end int) bool {
	return start >= 0 && end >= start && end <= len(masked)
}

// overlapsAny reports whether [start,end) overlaps any already-resolved claim.
func overlapsAny(claims []claim, start, end int) bool {
	for _, c := range claims {
		if start < c.end && end > c.start {
			return true
		}
	}
	return false
}

// findUnclaimed returns the first occurrence of token in masked that does not
// overlap any range in claims. Returns ok=false when token is empty (an
// empty token cannot be located unambiguously) or no unclaimed occurrence
// exists.
func findUnclaimed(masked, token string, claims []claim) (start, end int, ok bool) {
	if token == "" {
		return 0, 0, false
	}
	searchFrom := 0
	for searchFrom <= len(masked) {
		idx := strings.Index(masked[searchFrom:], token)
		if idx < 0 {
			return 0, 0, false
		}
		start = searchFrom + idx
		end = start + len(token)
		if !overlapsAny(claims, start, end) {
			return start, end, true
		}
		searchFrom = start + 1
	}
	return 0, 0, false
}
