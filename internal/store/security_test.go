package store

import (
	"context"
	"testing"
	"time"
)

// TestMemoryHashIDNotRawKey verifies the internal map key is not the raw id,
// so a memory dump (or a debugger) does not expose payload ids directly.
func TestMemoryHashIDNotRawKey(t *testing.T) {
	m, err := NewMemory(testKey())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	defer m.Close()
	ctx := context.Background()
	if err := m.Save(ctx, "very-secret-payload-id", Record{Strategy: "partial"}, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	m.mu.RLock()
	_, rawPresent := m.items["very-secret-payload-id"]
	_, hashedPresent := m.items[m.HashID("very-secret-payload-id")]
	m.mu.RUnlock()
	if rawPresent {
		t.Errorf("raw id used as map key")
	}
	if !hashedPresent {
		t.Errorf("hashed id not found as map key")
	}
}

// TestHashIDDeterministicAndKeyed verifies HashID is deterministic for a given
// key+id, differs across ids and differs across keys (so it cannot be
// recomputed by a caller without the store's key).
func TestHashIDDeterministicAndKeyed(t *testing.T) {
	m1, _ := NewMemory(testKey())
	defer m1.Close()
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(255 - i)
	}
	m2, _ := NewMemory(otherKey)
	defer m2.Close()

	h1a := m1.HashID("doc-1")
	h1b := m1.HashID("doc-1")
	if h1a != h1b {
		t.Errorf("HashID not deterministic: %q vs %q", h1a, h1b)
	}
	if m1.HashID("doc-2") == h1a {
		t.Errorf("different ids hashed to the same value")
	}
	if m2.HashID("doc-1") == h1a {
		t.Errorf("HashID does not depend on the store key")
	}
	if len(h1a) != hashIDLen {
		t.Errorf("HashID length = %d, want %d", len(h1a), hashIDLen)
	}
}

// TestMemorySaveNewFirstWriteWins verifies SaveNew only writes when no live
// record exists, protecting the first concurrent writer for a given id.
func TestMemorySaveNewFirstWriteWins(t *testing.T) {
	m, err := NewMemory(testKey())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	created, err := m.SaveNew(ctx, "id1", Record{Strategy: "partial", Hash: "first"}, time.Minute)
	if err != nil {
		t.Fatalf("SaveNew: %v", err)
	}
	if !created {
		t.Fatalf("first SaveNew should report created=true")
	}

	created2, err := m.SaveNew(ctx, "id1", Record{Strategy: "partial", Hash: "second"}, time.Minute)
	if err != nil {
		t.Fatalf("SaveNew second: %v", err)
	}
	if created2 {
		t.Fatalf("second SaveNew should report created=false")
	}

	got, ok, err := m.Load(ctx, "id1")
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.Hash != "first" {
		t.Errorf("record overwritten: Hash = %q, want %q", got.Hash, "first")
	}
}

// TestMemorySaveNewAfterExpiry verifies SaveNew allows a fresh write once the
// previous record has expired.
func TestMemorySaveNewAfterExpiry(t *testing.T) {
	m, err := NewMemory(testKey())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	if _, err := m.SaveNew(ctx, "id1", Record{Hash: "first"}, 50*time.Millisecond); err != nil {
		t.Fatalf("SaveNew: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	created, err := m.SaveNew(ctx, "id1", Record{Hash: "second"}, time.Minute)
	if err != nil {
		t.Fatalf("SaveNew after expiry: %v", err)
	}
	if !created {
		t.Errorf("SaveNew after expiry should report created=true")
	}
}
