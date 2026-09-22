package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"pdn-shield/internal/mask"
	"pdn-shield/internal/pii"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestMemorySaveLoad(t *testing.T) {
	m, err := NewMemory(testKey())
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	rec := Record{
		Replacements: []mask.Replacement{
			{Category: pii.CatPhone, Original: "+7 (916) 123-45-67", Masked: "+7 (9**) ***-**-67", Start: 0, End: 17},
		},
		Strategy:   "partial",
		CreatedAt:  time.Now(),
		MaskedText: "+7 (9**) ***-**-67",
		Hash:       "abc",
	}
	if err := m.Save(ctx, "id1", rec, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := m.Load(ctx, "id1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("Load: not found")
	}
	if got.Strategy != "partial" || got.Hash != "abc" || len(got.Replacements) != 1 {
		t.Errorf("loaded record mismatch: %+v", got)
	}
	if got.Replacements[0].Original != "+7 (916) 123-45-67" {
		t.Errorf("replacement original mismatch: %q", got.Replacements[0].Original)
	}
}

func TestMemoryDelete(t *testing.T) {
	m, _ := NewMemory(testKey())
	defer m.Close()
	ctx := context.Background()
	m.Save(ctx, "id", Record{Strategy: "partial"}, time.Minute)
	if err := m.Delete(ctx, "id"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := m.Load(ctx, "id"); ok {
		t.Error("record still present after Delete")
	}
}

func TestMemoryExpire(t *testing.T) {
	m, _ := NewMemory(testKey())
	defer m.Close()
	ctx := context.Background()
	m.Save(ctx, "id", Record{Strategy: "partial"}, 100*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	if _, ok, _ := m.Load(ctx, "id"); ok {
		t.Error("record not expired")
	}
}

func TestMemoryConcurrent(t *testing.T) {
	m, _ := NewMemory(testKey())
	defer m.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := "id" + string(rune('a'+n%26))
			m.Save(ctx, id, Record{Strategy: "partial", Hash: "h"}, time.Minute)
			m.Load(ctx, id)
			m.Delete(ctx, id)
		}(i)
	}
	wg.Wait()
}
