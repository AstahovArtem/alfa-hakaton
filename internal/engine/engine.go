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

// ErrNotFound is returned when an id is unknown.
var ErrNotFound = errors.New("engine: record not found")

// ErrLooksLikeUnmask is returned when a Mask call receives text that equals the
// stored masked text, indicating the caller actually wants to unmask.
var ErrLooksLikeUnmask = errors.New("engine: text looks like an unmask request")

// ErrForeignRecord is returned by MaskEx/MaskBatchEx when a record already
// exists under the requested id but belongs to a different system. The
// caller must never overwrite it.
var ErrForeignRecord = errors.New("engine: record belongs to another system")

// Options configures a single Mask call.
type Options struct {
	Categories []pii.Category // empty = all
	Strategy   string         // partial|token|synthetic
	TTL        time.Duration
	ComboRules []ComboRule
	// Unmask, when false, forbids Process from restoring a stored mask: a
	// payload that equals the stored mask is returned as-is (the mask itself)
	// rather than unmasked.
	Unmask bool
	// SystemID is the authenticated caller's system id. It is recorded as the
	// owner of any record this call creates, and is compared against a
	// record's owner before Process/MaskEx/MaskBatchEx/UnmaskEx are allowed
	// to read or extend an existing record.
	SystemID string
	// DefaultSystemID is the configured default system id (server.default_system).
	// A record with no recorded owner (written before ownership tracking
	// existed) is treated as owned by this system only.
	DefaultSystemID string
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
func (e *Engine) MaskBatch(
	ctx context.Context,
	id string,
	texts []string,
	opt Options,
) ([]string, map[pii.Category]int, error) {
	res, err := e.MaskBatchEx(ctx, id, texts, opt)
	if err != nil {
		return nil, nil, err
	}
	return res.Masked, res.Found, nil
}

// MaskBatchEx is MaskBatch with stage timings in the result. Each message's
// replacements are shifted by the cumulative length of the previously
// masked messages (matching how joinMasked concatenates them), so every
// Replacement's Start/End is a position in the single stored MaskedText
// rather than colliding local, per-message offsets: without this, two
// messages containing the same value would both record a replacement
// starting at 0, and Restore could not tell them apart.
func (e *Engine) MaskBatchEx(ctx context.Context, id string, texts []string, opt Options) (MaskBatchResult, error) {
	if rec, ok, err := e.store.Load(ctx, id); err == nil && ok && !ownsRecord(rec, opt) {
		return MaskBatchResult{}, ErrForeignRecord
	}

	doc := mask.NewDocState()
	strategy := e.resolveStrategy(opt.Strategy)
	if strategy == nil {
		return MaskBatchResult{}, errors.New("engine: no strategy available")
	}

	masked := make([]string, len(texts))
	var allReps []mask.Replacement
	found := make(map[pii.Category]int)
	var stages Stages
	msgOffset := 0
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
		for _, r := range reps {
			r.Start += msgOffset
			r.End += msgOffset
			allReps = append(allReps, r)
		}
		for c, n := range f {
			found[c] += n
		}
		// +1 for the '\n' separator joinMasked writes after every message.
		msgOffset += len(masked[i]) + 1
	}

	rec := store.Record{
		Replacements: allReps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   joinMasked(masked),
		Hash:         hashText(joinTexts(texts)),
		SystemID:     opt.SystemID,
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
		if !ownsRecord(rec, opt) {
			return MaskResult{}, ErrForeignRecord
		}
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

// resolveStrategy returns the strategy for name, falling back to "partial" and
// then to any registered strategy. It returns nil when no strategy is known.
func (e *Engine) resolveStrategy(name string) mask.Strategy {
	strategy := e.strategies[name]
	if strategy == nil {
		strategy = e.strategies["partial"]
	}
	if strategy == nil {
		for _, s := range e.strategies {
			strategy = s
			break
		}
	}
	return strategy
}

// runMask runs detection and masking for text (chunked when large) without
// touching the store. It is the shared core of every code path that produces
// a masked result, whether or not that result ends up persisted.
func (e *Engine) runMask(text string, opt Options, strategy mask.Strategy, doc *mask.DocState) (MaskResult, []mask.Replacement) {
	var masked string
	var reps []mask.Replacement
	var found map[pii.Category]int
	var stages Stages

	if len(text) > chunkThreshold {
		masked, reps, found, stages = e.maskChunked(text, opt, strategy, doc)
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
	return MaskResult{Masked: masked, Found: found, Stages: stages}, reps
}

// maskOnly masks text and returns the result without persisting anything. It
// is used whenever a payload must be masked but the outcome must not be
// saved: a record owned by a different system, or a payload that does not
// match any known state of an existing record.
func (e *Engine) maskOnly(text string, opt Options, doc *mask.DocState) (MaskResult, error) {
	strategy := e.resolveStrategy(opt.Strategy)
	if strategy == nil {
		return MaskResult{}, errors.New("engine: no strategy available")
	}
	mres, _ := e.runMask(text, opt, strategy, doc)
	return mres, nil
}

// maskWithRecord masks text and saves the mapping under id. existing, when
// non-nil, is a record already loaded by the caller (and already verified to
// be owned by opt.SystemID) so the store is not hit a second time.
func (e *Engine) maskWithRecord(
	ctx context.Context,
	id, text string,
	opt Options,
	doc *mask.DocState,
	existing *store.Record,
) (MaskResult, error) {
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

	strategy := e.resolveStrategy(opt.Strategy)
	if strategy == nil {
		return MaskResult{}, errors.New("engine: no strategy available")
	}
	mres, reps := e.runMask(text, opt, strategy, doc)

	rec := store.Record{
		Replacements: reps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   mres.Masked,
		Hash:         hash,
		SystemID:     opt.SystemID,
	}
	storeStart := time.Now()
	if err := e.store.Save(ctx, id, rec, opt.TTL); err != nil {
		return MaskResult{}, err
	}
	mres.Stages.StoreMs = time.Since(storeStart).Milliseconds()
	return mres, nil
}

// Unmask loads the mapping by id and restores the original text.
func (e *Engine) Unmask(ctx context.Context, id, masked string, opt Options) (string, int, error) {
	res, err := e.UnmaskEx(ctx, id, masked, opt)
	if err != nil {
		return "", 0, err
	}
	return res.Restored, res.Misses, nil
}

// UnmaskEx is Unmask with stage timings in the result. A record that exists
// but belongs to a different system is reported as ErrNotFound, exactly like
// a missing id: the caller must not learn that a foreign record exists.
func (e *Engine) UnmaskEx(ctx context.Context, id, masked string, opt Options) (UnmaskResult, error) {
	loadStart := time.Now()
	rec, ok, err := e.store.Load(ctx, id)
	if err != nil {
		return UnmaskResult{}, err
	}
	if !ok || !ownsRecord(rec, opt) {
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
// the id is known but owned by a different system, the payload is masked
// fresh and returned without ever reading or overwriting the foreign record.
// A brand-new id is persisted with SET NX (SaveNew) so two concurrent first
// writers for the same id cannot silently clobber one another: the loser
// resolves through the normal existing-record path instead.
func (e *Engine) Process(ctx context.Context, id, payload string, opt Options) (ProcessResult, error) {
	loadStart := time.Now()
	rec, exists, err := e.store.Load(ctx, id)
	if err != nil {
		return ProcessResult{}, err
	}
	loadMs := time.Since(loadStart).Milliseconds()

	if exists {
		if !ownsRecord(rec, opt) {
			return e.maskFreshResult(payload, opt)
		}
		res, err := e.processExisting(rec, payload, opt)
		if err != nil {
			return ProcessResult{}, err
		}
		// The idempotent-retry and restore paths do not otherwise record the
		// store timing (only the Load above touched the store, no Save), and
		// the idempotent retry does not otherwise report found counts.
		res.Stages.StoreMs += loadMs
		if !res.Unmasked && res.Found == nil && res.Result == rec.MaskedText {
			res.Found = countsFromRec(rec)
		}
		return res, nil
	}

	strategy := e.resolveStrategy(opt.Strategy)
	if strategy == nil {
		return ProcessResult{}, errors.New("engine: no strategy available")
	}
	mres, reps := e.runMask(payload, opt, strategy, mask.NewDocState())
	newRec := store.Record{
		Replacements: reps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   mres.Masked,
		Hash:         hashText(payload),
		SystemID:     opt.SystemID,
	}
	storeStart := time.Now()
	created, err := e.store.SaveNew(ctx, id, newRec, opt.TTL)
	if err != nil {
		return ProcessResult{}, err
	}
	mres.Stages.StoreMs = time.Since(storeStart).Milliseconds()
	if created {
		return ProcessResult{Result: mres.Masked, Found: mres.Found, Stages: mres.Stages}, nil
	}

	// Lost the race: another request created the record first. Resolve
	// through the normal existing-record path instead of overwriting it.
	rec2, ok, err := e.store.Load(ctx, id)
	if err != nil {
		return ProcessResult{}, err
	}
	if !ok {
		// The winner's record vanished (e.g. expired) between SaveNew and
		// this Load; fall back to a plain save of our own result.
		if err := e.store.Save(ctx, id, newRec, opt.TTL); err != nil {
			return ProcessResult{}, err
		}
		return ProcessResult{Result: mres.Masked, Found: mres.Found, Stages: mres.Stages}, nil
	}
	if !ownsRecord(rec2, opt) {
		return e.maskFreshResult(payload, opt)
	}
	return e.processExisting(rec2, payload, opt)
}

// maskFreshResult masks payload without persisting anything, for a caller
// that must never read or extend a record it does not own.
func (e *Engine) maskFreshResult(payload string, opt Options) (ProcessResult, error) {
	mres, err := e.maskOnly(payload, opt, mask.NewDocState())
	if err != nil {
		return ProcessResult{}, err
	}
	return ProcessResult{Result: mres.Masked, Found: mres.Found, Stages: mres.Stages}, nil
}

// processExisting resolves a Process call against a record already verified
// to be owned by the caller (opt.SystemID).
//
// The unmask permission (opt.Unmask) is checked before any restore is
// attempted, not just when the payload happens to equal the stored mask: a
// system with unmask disabled must never see a restored value, regardless of
// what the payload looks like.
//
//   - payload equals the original text (hash match): return the stored mask
//     (idempotent retry; allowed regardless of opt.Unmask, since nothing is
//     restored).
//   - opt.Unmask is false: never restore. Mask the payload fresh with the
//     caller's strategy/categories and return that, without touching the
//     stored record.
//   - payload equals the stored mask, or a partial/reordered variant of it:
//     restore what matches. If nothing at all matches, this is not our mask;
//     mask the payload fresh instead of leaking it unchanged (this also
//     covers a record with zero recorded replacements, where "restoring"
//     would otherwise trivially return the payload as-is).
func (e *Engine) processExisting(rec store.Record, payload string, opt Options) (ProcessResult, error) {
	if rec.Hash == hashText(payload) {
		return ProcessResult{Result: rec.MaskedText}, nil
	}
	if !opt.Unmask {
		return e.maskFreshResult(payload, opt)
	}
	restored, misses := mask.Restore(payload, rec.Replacements)
	if misses >= len(rec.Replacements) {
		return e.maskFreshResult(payload, opt)
	}
	return ProcessResult{Result: restored, Unmasked: true, Misses: misses}, nil
}

// ownsRecord reports whether opt.SystemID may access rec. A record with no
// recorded owner (SystemID == store.LegacyOwner, i.e. written before
// ownership tracking existed) is accessible only to the configured default
// system, never to an arbitrary other caller.
func ownsRecord(rec store.Record, opt Options) bool {
	if rec.SystemID == store.LegacyOwner {
		return opt.SystemID != "" && opt.SystemID == opt.DefaultSystemID
	}
	return rec.SystemID == opt.SystemID
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
