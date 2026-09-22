package store

import (
	"context"
	"os"
	"testing"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
)

// TestRedisStore is skipped unless REDIS_ADDR is set.
func TestRedisStore(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set, skipping redis test")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	rs, err := NewRedis(addr, "", key, 4)
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	defer rs.Close()

	ctx := context.Background()
	if err := rs.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	rec := Record{
		Replacements: []mask.Replacement{
			{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "+7 (9**) ***-**-**", Start: 0, End: 16},
		},
		Strategy:   "partial",
		CreatedAt:  time.Now(),
		MaskedText: "+7 (9**) ***-**-**",
		Hash:       "abc",
	}
	if err := rs.Save(ctx, "redis-test-id", rec, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := rs.Load(ctx, "redis-test-id")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatalf("record not found")
	}
	if got.MaskedText != rec.MaskedText {
		t.Errorf("MaskedText = %q, want %q", got.MaskedText, rec.MaskedText)
	}
	if len(got.Replacements) != 1 || got.Replacements[0].Original != rec.Replacements[0].Original {
		t.Errorf("replacements mismatch: %+v", got.Replacements)
	}
	if err := rs.Delete(ctx, "redis-test-id"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = rs.Load(ctx, "redis-test-id")
	if err != nil {
		t.Fatalf("Load after delete: %v", err)
	}
	if ok {
		t.Errorf("record still present after delete")
	}
}
