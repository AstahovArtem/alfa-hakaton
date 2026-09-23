// Package store persists masking records so the original text can be restored.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"pdn-shield/internal/mask"
)

// hashIDLen is the number of hex characters kept from the HMAC digest: 16 hex
// chars (64 bits) is enough to avoid collisions for a log/key namespace while
// keeping the id short and non-reversible.
const hashIDLen = 16

// hashID derives a short, non-reversible identifier from id using HMAC-SHA256
// keyed by the store's encryption key (or a key derived from it). It is used
// both as the Redis storage key and as the value logged for a payload id, so
// the raw payload id never appears in logs or in the store.
func hashID(key []byte, id string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum)[:hashIDLen]
}

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
	// SystemID is the id of the authenticated system that created the
	// record. It is used to reject access to a record from any other
	// system. A record decoded with an empty SystemID is a legacy record
	// (written before ownership was tracked): callers treat it as owned by
	// the default system only, never by an arbitrary other system.
	SystemID string
}

// LegacyOwner is the pseudo owner assigned to records with no SystemID, i.e.
// records written before ownership tracking existed. Only the default system
// may access them, so pass the configured default system id where an owner
// check against a legacy record is performed.
const LegacyOwner = ""

// Store is the persistence interface for records.
type Store interface {
	Save(ctx context.Context, id string, rec Record, ttl time.Duration) error
	// SaveNew saves rec under id only if no record currently exists for id
	// (first write wins). created is true when the record was written; when
	// false, a record already existed and was left untouched, and the
	// caller should Load it and proceed through the existing-record path.
	SaveNew(ctx context.Context, id string, rec Record, ttl time.Duration) (created bool, err error)
	Load(ctx context.Context, id string) (Record, bool, error)
	Delete(ctx context.Context, id string) error
	// Ping reports whether the store is reachable.
	Ping(ctx context.Context) error
	// HashID returns a short, non-reversible identifier derived from id via
	// HMAC-SHA256 with the store's encryption key. It is safe to log and to
	// use as the on-the-wire storage key so the raw payload id never appears
	// in Redis or in logs.
	HashID(id string) string
}
