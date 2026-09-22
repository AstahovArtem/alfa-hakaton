package pii

import "sort"

// Resolve sorts spans and removes overlaps.
// Spans are sorted by Start; on equal Start the longer one comes first.
// On overlap the span with the higher Confidence wins; on equal confidence the longer one wins.
func Resolve(spans []Span) []Span {
	if len(spans) == 0 {
		return nil
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End > spans[j].End
	})

	out := make([]Span, 0, len(spans))
	for _, s := range spans {
		if len(out) == 0 {
			out = append(out, s)
			continue
		}
		last := &out[len(out)-1]
		if s.Start >= last.End {
			out = append(out, s)
			continue
		}
		// Overlap: keep the winner.
		if better(s, *last) {
			*last = s
		}
	}
	return out
}

// better reports whether a should replace b on overlap.
func better(a, b Span) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return a.End-a.Start > b.End-b.Start
}
