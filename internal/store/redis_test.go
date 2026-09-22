package store

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
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

// fakeRedisServer accepts TCP connections and answers every command with +OK.
// It counts the number of accepted connections.
type fakeRedisServer struct {
	ln     net.Listener
	accept atomic.Int64
}

func newFakeRedisServer(t *testing.T) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeRedisServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.accept.Add(1)
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				if _, err := readRESP(br); err != nil {
					return
				}
				// Reply +OK to every command.
				if _, err := c.Write([]byte("+OK\r\n")); err != nil {
					return
				}
			}
		}(conn)
	}
}

func (s *fakeRedisServer) addr() string { return s.ln.Addr().String() }

// TestRedisPoolFixedSize verifies that under heavy concurrency the pool opens
// no more than poolSize connections and no call fails.
func TestRedisPoolFixedSize(t *testing.T) {
	srv := newFakeRedisServer(t)
	rs, err := NewRedisWithOptions(srv.addr(), "", testKey(), Options{
		PoolSize: 8,
		Wait:     2 * time.Second,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewRedisWithOptions: %v", err)
	}
	defer rs.Close()

	ctx := context.Background()
	const calls = 500
	var wg sync.WaitGroup
	errs := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("id-%d", n)
			if err := rs.Save(ctx, id, Record{Strategy: "partial", Hash: "h"}, time.Minute); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("call failed: %v", err)
	}

	if got := srv.accept.Load(); got > 8 {
		t.Errorf("pool opened %d connections, want <= 8", got)
	}
}
