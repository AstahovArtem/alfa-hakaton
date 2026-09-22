package store

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"pdn-shield/internal/crypto"
)

// memoryEntry is a stored ciphertext with its expiry.
type memoryEntry struct {
	ct     []byte
	expiry time.Time
}

// Memory is an in-memory Store with TTL-based background cleanup. Records are
// stored encrypted so a memory dump does not reveal personal data.
type Memory struct {
	mu     sync.RWMutex
	items  map[string]memoryEntry
	cipher *crypto.Cipher
	stop   chan struct{}
	done   chan struct{}
}

// NewMemory creates a Memory store. The key must be 32 bytes.
func NewMemory(key []byte) (*Memory, error) {
	c, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	m := &Memory{
		items:  make(map[string]memoryEntry),
		cipher: c,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go m.cleanupLoop()
	return m, nil
}

// cleanupLoop periodically removes expired entries.
func (m *Memory) cleanupLoop() {
	defer close(m.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			for id, e := range m.items {
				if !e.expiry.IsZero() && now.After(e.expiry) {
					delete(m.items, id)
				}
			}
			m.mu.Unlock()
		}
	}
}

// Close stops the background cleanup goroutine.
func (m *Memory) Close() {
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
		<-m.done
	}
}

// Save encrypts and stores a record under id with the given TTL.
func (m *Memory) Save(_ context.Context, id string, rec Record, ttl time.Duration) error {
	plain, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ct, err := m.cipher.Encrypt(plain)
	if err != nil {
		return err
	}
	var expiry time.Time
	if ttl > 0 {
		expiry = time.Now().Add(ttl)
	}
	m.mu.Lock()
	m.items[id] = memoryEntry{ct: ct, expiry: expiry}
	m.mu.Unlock()
	return nil
}

// Load retrieves and decrypts a record by id.
func (m *Memory) Load(_ context.Context, id string) (Record, bool, error) {
	m.mu.RLock()
	e, ok := m.items[id]
	m.mu.RUnlock()
	if !ok {
		return Record{}, false, nil
	}
	if !e.expiry.IsZero() && time.Now().After(e.expiry) {
		m.mu.Lock()
		delete(m.items, id)
		m.mu.Unlock()
		return Record{}, false, nil
	}
	plain, err := m.cipher.Decrypt(e.ct)
	if err != nil {
		return Record{}, false, err
	}
	var rec Record
	if err := json.Unmarshal(plain, &rec); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

// Delete removes a record by id.
func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.items, id)
	m.mu.Unlock()
	return nil
}
