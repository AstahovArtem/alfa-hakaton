package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"pdn-shield/internal/crypto"
)

// Default pool and timeout values used when the caller does not override them.
const (
	DefaultRedisPoolSize = 64
	DefaultRedisWait     = 500 * time.Millisecond
	DefaultRedisTimeout  = 500 * time.Millisecond
	DefaultRedisDial     = time.Second
	DefaultRedisMinIdle  = 8
	// redisKeyPrefix is prepended to every stored key to namespace the records.
	redisKeyPrefix = "pdn:"
)

// Redis is a Store backed by a Redis server using go-redis.
type Redis struct {
	client *redis.Client
	cipher *crypto.Cipher
}

// Options configures the Redis client pool.
type Options struct {
	PoolSize int
	// Wait is the maximum time to wait for a free connection when the pool is
	// exhausted. Zero means DefaultRedisWait.
	Wait time.Duration
	// Timeout is the read/write timeout for a single command. Zero means
	// DefaultRedisTimeout.
	Timeout time.Duration
	// Dial is the connection dial timeout. Zero means DefaultRedisDial.
	Dial time.Duration
}

// NewRedis creates a Redis store. key must be 32 bytes. poolSize is the number
// of pooled connections.
func NewRedis(addr, password string, key []byte, poolSize int) (*Redis, error) {
	return NewRedisWithOptions(addr, password, key, Options{PoolSize: poolSize})
}

// NewRedisWithOptions creates a Redis store with explicit pool options.
func NewRedisWithOptions(addr, password string, key []byte, opt Options) (*Redis, error) {
	c, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	if opt.PoolSize <= 0 {
		opt.PoolSize = DefaultRedisPoolSize
	}
	if opt.Wait <= 0 {
		opt.Wait = DefaultRedisWait
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultRedisTimeout
	}
	if opt.Dial <= 0 {
		opt.Dial = DefaultRedisDial
	}
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  opt.Dial,
		ReadTimeout:  opt.Timeout,
		WriteTimeout: opt.Timeout,
		PoolSize:     opt.PoolSize,
		PoolTimeout:  opt.Wait,
		MinIdleConns: DefaultRedisMinIdle,
	})
	return &Redis{client: client, cipher: c}, nil
}

// Ping checks connectivity.
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close closes the client and its connection pool.
func (r *Redis) Close() {
	if r.client != nil {
		_ = r.client.Close()
	}
}

// Save encrypts and stores a record under id with the given TTL.
func (r *Redis) Save(ctx context.Context, id string, rec Record, ttl time.Duration) error {
	plain, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ct, err := r.cipher.Encrypt(plain)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, redisKeyPrefix+id, ct, ttl).Err()
}

// Load retrieves and decrypts a record by id.
func (r *Redis) Load(ctx context.Context, id string) (Record, bool, error) {
	ct, err := r.client.Get(ctx, redisKeyPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	plain, err := r.cipher.Decrypt(ct)
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
func (r *Redis) Delete(ctx context.Context, id string) error {
	return r.client.Del(ctx, redisKeyPrefix+id).Err()
}
