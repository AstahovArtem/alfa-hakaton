// Package engine ties detection, masking and storage together.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// Mask detects, masks and saves the mapping under id. It returns the masked
// text and detected counts by category.
func (e *Engine) Mask(ctx context.Context, id, text string, opt Options) (string, map[pii.Category]int, error) {
	hash := hashText(text)

	// Idempotency: if the id exists and the hash matches, return the stored mask.
	if rec, ok, err := e.store.Load(ctx, id); err == nil && ok {
		if rec.Hash == hash {
			return rec.MaskedText, countsFromRec(rec), nil
		}
		// If the incoming text equals the stored masked text, this is an unmask
		// request.
		if rec.MaskedText == text {
			return "", nil, ErrLooksLikeUnmask
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
		return "", nil, errors.New("engine: no strategy available")
	}

	res := e.pipeline.Run(text)
	spans := filterSpans(res.Spans, opt.Categories, opt.ComboRules)

	doc := mask.NewDocState()
	masked, reps := mask.Apply(text, spans, strategy, doc)

	rec := store.Record{
		Replacements: reps,
		Strategy:     strategy.Name(),
		CreatedAt:    time.Now(),
		MaskedText:   masked,
		Hash:         hash,
	}
	if err := e.store.Save(ctx, id, rec, opt.TTL); err != nil {
		return "", nil, err
	}
	return masked, counts(spans), nil
}

// Unmask loads the mapping by id and restores the original text.
func (e *Engine) Unmask(ctx context.Context, id, masked string) (string, int, error) {
	rec, ok, err := e.store.Load(ctx, id)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, ErrNotFound
	}
	restored, misses := mask.Restore(masked, rec.Replacements)
	return restored, misses, nil
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
