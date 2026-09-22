// Package store persists masking records so the original text can be restored.
package store

import (
	"context"
	"time"

	"pdn-shield/internal/mask"
)

// Record is one stored masking mapping.
type Record struct {
	Replacements []mask.Replacement
	Strategy     string
	CreatedAt    time.Time
	// MaskedText is the masked output, used for idempotency and to detect
	// unmask requests.
	MaskedText string
	// Hash is the SHA-256 of the original text, used for idempotency.
	Hash string
}

// Store is the persistence interface for records.
type Store interface {
	Save(ctx context.Context, id string, rec Record, ttl time.Duration) error
	Load(ctx context.Context, id string) (Record, bool, error)
	Delete(ctx context.Context, id string) error
}
