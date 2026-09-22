// Package engine ties detection, masking and storage together.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
	"pdn-shield/internal/store"
)

// chunkThreshold is the text size above which Mask splits the input into
// chunks before running the pipeline.
const chunkThreshold = 64 * 1024

// chunkSize is the target chunk size in bytes.
const chunkSize = 32 * 1024

// ErrNotFound is returned when an id is unknown.
var ErrNotFound = errors.New("engine: record not found")

// ErrLooksLikeUnmask is returned when a Mask call receives text that equals the
// stored masked text, indicating the caller actually wants to unmask.
var ErrLooksLikeUnmask = errors.New("engine: text looks like an unmask request")

// Options configures a single Mask call.
type Options struct {
	Categories []pii.Category // empty = all
	Strategy   string         // partial|token|synthetic
	TTL        time.Duration
	ComboRules []ComboRule
}

// ComboRule masks Category only if at least one of RequiresAny is present in
// the document.
type ComboRule struct {
	Category    pii.Category
	RequiresAny []pii.Category
}

// Engine runs the pipeline, masks text and persists the mapping.
type Engine struct {
	pipeline   *pii.Pipeline
	store      store.Store
	strategies map[string]mask.Strategy
}

// New builds an Engine.
func New(p *pii.Pipeline, st store.Store, strategies map[string]mask.Strategy) *Engine {
	return &Engine{pipeline: p, store: st, strategies: strategies}
}

// Stages holds the durations of the pipeline stages for a request, in
// milliseconds. Zero values mean the stage did not run.
type Stages struct {
	DetectMs int64
	MaskMs   int64
	StoreMs  int64
	LLMMs    int64
}

// MaskResult is the extended result of a Mask call, including stage timings.
type MaskResult struct {
	Masked string
	Found  map[pii.Category]int
	Stages Stages
}

// MaskBatchResult is the extended result of a MaskBatch call, including stage
// timings.
type MaskBatchResult struct {
	Masked []string
	Found  map[pii.Category]int
	Stages Stages
}

// UnmaskResult is the extended result of an Unmask call, including stage
// timings.
type UnmaskResult struct {
	Restored string
	Misses   int
	Stages   Stages
}

// Mask detects, masks and saves the mapping under id. It returns the masked
// text and detected counts by category.
func (e *Engine) Mask(ctx context.Context, id, text string, opt Options) (string, map[pii.Category]int, error) {
	res, err := e.MaskEx(ctx, id, text, opt)
	if err != nil {
		return "", nil, err
	}
	return res.Masked, res.Found, nil
}

// MaskEx is Mask with stage timings in the result.
func (e *Engine) MaskEx(ctx context.Context, id, text string, opt Options) (MaskResult, error) {
	return e.maskEx(ctx, id, text, opt, mask.NewDocState())
}

// MaskBatch masks several texts under one id with a shared DocState so equal
// values across texts get the same replacement. All replacements are saved in
// a single record, so the LLM response can be unmasked with one id. It returns
// the masked texts and the combined counts.
func (e *Engine) MaskBatch(ctx context.Context, id string, texts []string, opt Options) ([]string, map[pii.Category]int, error) {
	res, err := e.MaskBatchEx(ctx, id, texts, opt)
	if err != nil {
		return nil, nil, err
	}
	return res.Masked, res.Found, nil
}

// MaskBatchEx is MaskBatch with stage timings in the result.
func (e *Engine) MaskBatchEx(ctx context.Context, id string, texts []string, opt Options) (MaskBatchResult, error) {
	doc := mask.NewDocState()
	strategy := e.strategies[opt.Strategy]
	if strategy == nil {
		strategy = e.strategies["partial"]
	}
	if strategy == nil {
		for _, s := range e.strategies {
			strategy = s
			break
		}
	}
	if strategy == nil {
		return MaskBatchResult{}, errors.New("engine: no strategy available")
	}

	masked := make([]string, len(texts))
	var allReps []mask.Replacement
	found := make(map[pii.Category]int)
	var stages Stages
	for i, text := range texts {
		var reps []mask.Replacement
		var f map[pii.Category]int
		if len(text) > chunkThreshold {
			var m string
			var st Stages
			m, reps, f, st = e.maskChunked(text, opt, strategy, doc)
			masked[i] = m
			stages.DetectMs += st.DetectMs
			stages.MaskMs += st.MaskMs
		} else {
			detectStart := time.Now()
			res := e.pipeline.Run(text)
			stages.DetectMs += time.Since(detectStart).Milliseconds()

			maskStart := time.Now()
			spans := filterSpans(res.Spans, opt.Categories, opt.ComboRules)
			masked[i], reps = mask.Apply(text, spans, strategy, doc)
			stages.MaskMs += time.Since(maskStart).Milliseconds()
			f = counts(spans)
		}
		allReps = append(allReps, reps...)
		for c, n := range f {
			found[c] += n
		}
	}

	rec := store.Record{
		Replacements: allReps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   joinMasked(masked),
		Hash:         hashText(joinTexts(texts)),
	}
	storeStart := time.Now()
	if err := e.store.Save(ctx, id, rec, opt.TTL); err != nil {
		return MaskBatchResult{}, err
	}
	stages.StoreMs = time.Since(storeStart).Milliseconds()
	return MaskBatchResult{Masked: masked, Found: found, Stages: stages}, nil
}

// joinMasked joins masked texts for the stored record.
func joinMasked(masked []string) string {
	var b strings.Builder
	for _, m := range masked {
		b.WriteString(m)
		b.WriteByte('\n')
	}
	return b.String()
}

// joinTexts joins original texts for hashing.
func joinTexts(texts []string) string {
	var b strings.Builder
	for _, t := range texts {
		b.WriteString(t)
		b.WriteByte('\n')
	}
	return b.String()
}

func (e *Engine) maskEx(ctx context.Context, id, text string, opt Options, doc *mask.DocState) (MaskResult, error) {
	hash := hashText(text)

	// Idempotency: if the id exists and the hash matches, return the stored mask.
	if rec, ok, err := e.store.Load(ctx, id); err == nil && ok {
		if rec.Hash == hash {
			return MaskResult{Masked: rec.MaskedText, Found: countsFromRec(rec)}, nil
		}
		// If the incoming text equals the stored masked text, this is an unmask
		// request.
		if rec.MaskedText == text {
			return MaskResult{}, ErrLooksLikeUnmask
		}
		return e.maskWithRecord(ctx, id, text, opt, doc, &rec)
	}
	return e.maskWithRecord(ctx, id, text, opt, doc, nil)
}

// maskWithRecord masks text and saves the mapping under id. existing, when
// non-nil, is a record already loaded by the caller so the store is not hit a
// second time.
func (e *Engine) maskWithRecord(ctx context.Context, id, text string, opt Options, doc *mask.DocState, existing *store.Record) (MaskResult, error) {
	hash := hashText(text)

	// Idempotency: if the caller already loaded a record with a matching hash,
	// return the stored mask without re-loading.
	if existing != nil {
		if existing.Hash == hash {
			return MaskResult{Masked: existing.MaskedText, Found: countsFromRec(*existing)}, nil
		}
		// If the incoming text equals the stored masked text, this is an unmask
		// request.
		if existing.MaskedText == text {
			return MaskResult{}, ErrLooksLikeUnmask
		}
	}

	strategy := e.strategies[opt.Strategy]
	if strategy == nil {
		strategy = e.strategies["partial"]
	}
	if strategy == nil {
		for _, s := range e.strategies {
			strategy = s
			break
		}
	}
	if strategy == nil {
		return MaskResult{}, errors.New("engine: no strategy available")
	}

	var masked string
	var reps []mask.Replacement
	var found map[pii.Category]int
	var stages Stages

	if len(text) > chunkThreshold {
		var st Stages
		masked, reps, found, st = e.maskChunked(text, opt, strategy, doc)
		stages = st
	} else {
		detectStart := time.Now()
		res := e.pipeline.Run(text)
		stages.DetectMs = time.Since(detectStart).Milliseconds()

		maskStart := time.Now()
		spans := filterSpans(res.Spans, opt.Categories, opt.ComboRules)
		masked, reps = mask.Apply(text, spans, strategy, doc)
		stages.MaskMs = time.Since(maskStart).Milliseconds()
		found = counts(spans)
	}

	rec := store.Record{
		Replacements: reps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   masked,
		Hash:         hash,
	}
	storeStart := time.Now()
	if err := e.store.Save(ctx, id, rec, opt.TTL); err != nil {
		return MaskResult{}, err
	}
	stages.StoreMs = time.Since(storeStart).Milliseconds()
	return MaskResult{Masked: masked, Found: found, Stages: stages}, nil
}

// maskChunked splits text into chunks, masks each chunk independently and
// concatenates the results. Replacement offsets are shifted by the chunk
// offset so they refer to the full masked text.
func (e *Engine) maskChunked(text string, opt Options, strategy mask.Strategy, doc *mask.DocState) (string, []mask.Replacement, map[pii.Category]int, Stages) {
	var b strings.Builder
	var reps []mask.Replacement
	found := make(map[pii.Category]int)
	var stages Stages
	offset := 0
	for _, chunk := range chunkText(text) {
		detectStart := time.Now()
		res := e.pipeline.Run(chunk)
		stages.DetectMs += time.Since(detectStart).Milliseconds()

		maskStart := time.Now()
		spans := filterSpans(res.Spans, opt.Categories, opt.ComboRules)
		masked, chunkReps := mask.Apply(chunk, spans, strategy, doc)
		stages.MaskMs += time.Since(maskStart).Milliseconds()
		for _, r := range chunkReps {
			r.Start += offset
			r.End += offset
			reps = append(reps, r)
		}
		for c, n := range counts(spans) {
			found[c] += n
		}
		b.WriteString(masked)
		offset += len(masked)
	}
	return b.String(), reps, found, stages
}

// chunkText splits text into chunks of at most chunkSize bytes, breaking on
// sentence or line boundaries so a word is never cut in half.
func chunkText(text string) []string {
	if len(text) <= chunkSize {
		return []string{text}
	}
	var chunks []string
	start := 0
	for start < len(text) {
		end := start + chunkSize
		if end >= len(text) {
			chunks = append(chunks, text[start:])
			break
		}
		// Find a boundary at or before end: prefer a newline, then a sentence
		// end, then a space.
		cut := findBoundary(text, start, end)
		chunks = append(chunks, text[start:cut])
		start = cut
	}
	return chunks
}

// findBoundary returns the best split point in text[start:end], preferring a
// newline, then a sentence end, then a space. It never splits a word.
func findBoundary(text string, start, end int) int {
	// Prefer a newline.
	for i := end; i > start; i-- {
		if text[i-1] == '\n' {
			return i
		}
	}
	// Then a sentence end followed by a space.
	for i := end; i > start; i-- {
		if text[i-1] == '.' || text[i-1] == '!' || text[i-1] == '?' {
			if i < len(text) && text[i] == ' ' {
				return i + 1
			}
			return i
		}
	}
	// Then a space.
	for i := end; i > start; i-- {
		if text[i-1] == ' ' {
			return i
		}
	}
	// Fall back to the hard limit.
	return end
}

// Unmask loads the mapping by id and restores the original text.
func (e *Engine) Unmask(ctx context.Context, id, masked string) (string, int, error) {
	res, err := e.UnmaskEx(ctx, id, masked)
	if err != nil {
		return "", 0, err
	}
	return res.Restored, res.Misses, nil
}

// UnmaskEx is Unmask with stage timings in the result.
func (e *Engine) UnmaskEx(ctx context.Context, id, masked string) (UnmaskResult, error) {
	loadStart := time.Now()
	rec, ok, err := e.store.Load(ctx, id)
	if err != nil {
		return UnmaskResult{}, err
	}
	if !ok {
		return UnmaskResult{}, ErrNotFound
	}
	loadMs := time.Since(loadStart).Milliseconds()
	restored, misses := mask.Restore(masked, rec.Replacements)
	return UnmaskResult{Restored: restored, Misses: misses, Stages: Stages{StoreMs: loadMs}}, nil
}

// ProcessResult describes the outcome of a Process call.
type ProcessResult struct {
	Result string
	// Found is the detected counts when the call masked new text.
	Found map[pii.Category]int
	// Unmasked is true when the call restored a stored mask.
	Unmasked bool
	// Misses is the number of unrecovered replacements during unmask.
	Misses int
	// Stages holds the stage timings for the call.
	Stages Stages
}

// Process implements the checker contract for a single payload. It masks the
// payload, or unmasks when the payload equals the stored mask, or returns the
// stored mask when the payload equals the original text (idempotency). When
// the id is known but the payload matches neither, it attempts an unmask and
// falls back to returning the payload as-is.
func (e *Engine) Process(ctx context.Context, id, payload string, opt Options) (ProcessResult, error) {
	rec, exists, err := e.store.Load(ctx, id)
	if err != nil {
		return ProcessResult{}, err
	}

	if exists {
		// Payload equals the stored mask: unmask.
		if rec.MaskedText == payload {
			restored, misses := mask.Restore(payload, rec.Replacements)
			return ProcessResult{Result: restored, Unmasked: true, Misses: misses}, nil
		}
		// Payload equals the original text: return the stored mask (idempotent).
		if rec.Hash == hashText(payload) {
			return ProcessResult{Result: rec.MaskedText}, nil
		}
		// Payload differs from both: try to unmask; the mask may have changed.
		restored, misses := mask.Restore(payload, rec.Replacements)
		if misses == 0 {
			return ProcessResult{Result: restored, Unmasked: true}, nil
		}
		// Zero matches: return the payload as-is.
		return ProcessResult{Result: payload, Misses: misses}, nil
	}

	// Unknown id: mask normally, reusing the already-loaded record so the store
	// is hit exactly once (1 GET + 1 SET).
	var existing *store.Record
	if exists {
		existing = &rec
	}
	mres, err := e.maskWithRecord(ctx, id, payload, opt, mask.NewDocState(), existing)
	if err != nil {
		return ProcessResult{}, err
	}
	return ProcessResult{Result: mres.Masked, Found: mres.Found, Stages: mres.Stages}, nil
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

func counts(spans []pii.Span) map[pii.Category]int {
	out := make(map[pii.Category]int)
	for _, s := range spans {
		out[s.Category]++
	}
	return out
}

func countsFromRec(rec store.Record) map[pii.Category]int {
	out := make(map[pii.Category]int)
	for _, r := range rec.Replacements {
		out[r.Category]++
	}
	return out
}

func hashText(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}
