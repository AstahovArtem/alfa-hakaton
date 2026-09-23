package engine

import (
	"runtime"
	"sync"
	"time"
	"unicode/utf8"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
)

// chunkThreshold is the text size above which Mask splits the input into
// overlapping detection windows instead of running the pipeline once over
// the whole text. The pipeline scales roughly linearly with text size (see
// pii/scale_test.go), but a single-threaded pass over a very large payload
// (hundreds of KB, as allowed by the "up to 100k tokens" input limit) still
// takes over a second; windowing lets the windows run in parallel and keeps
// per-request latency low.
const chunkThreshold = 64 * 1024

// chunkSize is the target size, in bytes, of a window's core region: the
// slice of the document a window is chiefly responsible for. Windows tile
// the whole text by their core regions.
const chunkSize = 32 * 1024

// chunkOverlap is how far a window extends beyond its core region on each
// side, in bytes. It must be large enough that:
//   - a value split across a core boundary (e.g. an email or a card number
//     landing right on the cut) is always fully contained, with room to
//     spare, in at least one window, never touching that window's own outer
//     edge;
//   - a label separated from its value by a core boundary (e.g. "паспорт
//     серия" on one side, the number on the other) stays together in one
//     window;
//   - the cross-span context lookups in pii/pipeline.go (postProcess reads
//     up to 200 runes, roughly 400 bytes for Cyrillic text, around a span)
//     always have their context available in every window that contains the
//     span they classify, so windows never disagree on a span's category.
//
// 4 KiB clears all of the above by a wide margin for any realistic PII value
// or label/value pair, while adding only modest overhead (about 12% extra
// bytes processed) relative to the 32 KiB core.
const chunkOverlap = 4 * 1024

// window is a byte range of text fed to the pipeline as one unit.
type window struct {
	start, end int
}

// windows splits text into overlapping detection windows. Consecutive
// windows share chunkOverlap bytes of context around the boundary between
// their core regions, so no entity or label/value pair is ever seen
// truncated by every window that could detect it. Boundaries only ever land
// on a whitespace/newline byte or a text edge; a token is never split, and
// since ASCII whitespace bytes cannot appear inside a multi-byte UTF-8
// sequence, a boundary chosen this way is always a valid rune boundary too.
// The rare fallback (an unbroken run of non-whitespace bytes longer than a
// window) still lands on a rune boundary, just not necessarily on a token
// boundary.
func windows(text string) []window {
	if len(text) <= chunkSize+2*chunkOverlap {
		return []window{{start: 0, end: len(text)}}
	}

	bounds := coreBoundaries(text)
	ws := make([]window, 0, len(bounds)-1)
	for i := 0; i+1 < len(bounds); i++ {
		ws = append(ws, window{
			start: extendBefore(text, bounds[i], chunkOverlap),
			end:   extendAfter(text, bounds[i+1], chunkOverlap),
		})
	}
	return ws
}

// coreBoundaries returns the cut points that tile text into core regions of
// about chunkSize bytes each, starting at 0 and ending at len(text). Each
// interior cut lands right after a whitespace/newline byte.
func coreBoundaries(text string) []int {
	bounds := []int{0}
	pos := 0
	for pos < len(text) {
		target := pos + chunkSize
		if target >= len(text) {
			break
		}
		cut := -1
		if i := indexLastBoundaryByte(text, pos, target); i >= 0 {
			cut = i + 1
		} else if i := indexFirstBoundaryByte(text, target, len(text)); i >= 0 {
			// No whitespace at all in [pos,target): an unusually long
			// unspaced run. Search forward past target rather than split it.
			cut = i + 1
		}
		if cut <= pos {
			break // rest of the text has no whitespace: keep it as one core.
		}
		bounds = append(bounds, cut)
		pos = cut
	}
	bounds = append(bounds, len(text))
	return bounds
}

// extendBefore moves pos left by about n bytes and then further left to just
// after the nearest whitespace byte, so the window does not start mid-token.
// It stops at the text start. If no whitespace is found in range it falls
// back to a rune-safe cut at pos-n.
func extendBefore(text string, pos, n int) int {
	lo := pos - n
	if lo < 0 {
		return 0
	}
	if i := indexLastBoundaryByte(text, 0, lo+1); i >= 0 {
		return i + 1
	}
	for lo > 0 && !utf8.RuneStart(text[lo]) {
		lo--
	}
	return lo
}

// extendAfter moves pos right by about n bytes and then further right to
// just before the nearest whitespace byte, so the window does not end
// mid-token. It stops at the text end. If no whitespace is found in range it
// falls back to a rune-safe cut at pos+n.
func extendAfter(text string, pos, n int) int {
	hi := pos + n
	if hi > len(text) {
		return len(text)
	}
	if i := indexFirstBoundaryByte(text, hi, len(text)); i >= 0 {
		return i
	}
	for hi < len(text) && !utf8.RuneStart(text[hi]) {
		hi++
	}
	return hi
}

// indexLastBoundaryByte returns the index of the last whitespace/newline
// byte in text[lo:hi], or -1 if none.
func indexLastBoundaryByte(text string, lo, hi int) int {
	for i := hi; i > lo; i-- {
		if isBoundaryByte(text[i-1]) {
			return i - 1
		}
	}
	return -1
}

// indexFirstBoundaryByte returns the index of the first whitespace/newline
// byte in text[lo:hi], or -1 if none.
func indexFirstBoundaryByte(text string, lo, hi int) int {
	for i := lo; i < hi; i++ {
		if isBoundaryByte(text[i]) {
			return i
		}
	}
	return -1
}

// isBoundaryByte reports whether b is a byte a window boundary may land on.
func isBoundaryByte(b byte) bool {
	return b == ' ' || b == '\n' || b == '\t' || b == '\r'
}

// detectWindowed runs the pipeline over text using overlapping windows
// (windows are processed in parallel) and merges the results into a single,
// document-level span list with global byte offsets, using the same
// pii.Resolve pass a short, unchunked text goes through. This is what makes
// the result equivalent to a single whole-text pipeline.Run: an entity split
// across a window boundary is fully detected in at least one window (see the
// chunkOverlap doc comment), duplicate detections of the same entity by
// adjacent windows collapse to one span, and genuine overlaps are resolved
// the usual way.
func detectWindowed(p *pii.Pipeline, text string) []pii.Span {
	ws := windows(text)
	if len(ws) == 1 {
		return p.Run(text).Spans
	}

	perWindow := make([][]pii.Span, len(ws))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i, w := range ws {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, w window) {
			defer wg.Done()
			defer func() { <-sem }()
			res := p.Run(text[w.start:w.end])
			spans := make([]pii.Span, len(res.Spans))
			for j, s := range res.Spans {
				s.Start += w.start
				s.End += w.start
				spans[j] = s
			}
			perWindow[i] = spans
		}(i, w)
	}
	wg.Wait()

	total := 0
	for _, spans := range perWindow {
		total += len(spans)
	}
	merged := make([]pii.Span, 0, total)
	for _, spans := range perWindow {
		merged = append(merged, spans...)
	}
	return pii.Resolve(merged)
}

// maskChunked masks a large text as a single document: it detects PII with
// overlapping windows (detectWindowed), applies the category filter and the
// combo rules once over the merged, document-level span list — so, for
// example, a card number found in one window and a PIN found in another
// still satisfy a combo rule requiring both, exactly as they would in a
// short, unchunked text — and then masks the whole original text in one
// mask.Apply call. Because the span list already carries global byte
// offsets into the untouched original text, no offset arithmetic is needed
// and replacement positions are correct by construction.
func (e *Engine) maskChunked(
	text string,
	opt Options,
	strategy mask.Strategy,
	doc *mask.DocState,
) (string, []mask.Replacement, map[pii.Category]int, Stages) {
	var stages Stages

	detectStart := time.Now()
	docSpans := detectWindowed(e.pipeline, text)
	stages.DetectMs = time.Since(detectStart).Milliseconds()

	maskStart := time.Now()
	spans := filterSpans(docSpans, opt.Categories, opt.ComboRules)
	masked, reps := mask.Apply(text, spans, strategy, doc)
	stages.MaskMs = time.Since(maskStart).Milliseconds()

	return masked, reps, counts(spans), stages
}

// filterSpans drops spans whose category is not in categories and applies the
// combo rules.
func filterSpans(spans []pii.Span, categories []pii.Category, rules []ComboRule) []pii.Span {
	wanted := make(map[pii.Category]bool)
	for _, c := range categories {
		wanted[c] = true
	}
	present := make(map[pii.Category]bool)
	for _, s := range spans {
		present[s.Category] = true
	}
	var out []pii.Span
	for _, s := range spans {
		if len(wanted) > 0 && !wanted[s.Category] {
			continue
		}
		if !comboAllowed(s.Category, present, rules) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// comboAllowed reports whether a category may be masked given the combo rules.
func comboAllowed(cat pii.Category, present map[pii.Category]bool, rules []ComboRule) bool {
	for _, r := range rules {
		if r.Category != cat {
			continue
		}
		for _, req := range r.RequiresAny {
			if present[req] {
				return true
			}
		}
		return false
	}
	return true
}
