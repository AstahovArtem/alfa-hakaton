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
	key    []byte
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
	return &Redis{client: client, cipher: c, key: key}, nil
}

// HashID returns the derived key used to store and log id.
func (r *Redis) HashID(id string) string {
	return hashID(r.key, id)
}

// redisKey returns the namespaced, hashed Redis key for id. The raw id never
// appears in Redis.
func (r *Redis) redisKey(id string) string {
	return redisKeyPrefix + r.HashID(id)
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
	ct, err := r.encode(rec)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, r.redisKey(id), ct, ttl).Err()
}

// SaveNew stores rec under id only if the key does not already exist, using
// Redis SET NX so the check and the write are atomic.
func (r *Redis) SaveNew(ctx context.Context, id string, rec Record, ttl time.Duration) (bool, error) {
	ct, err := r.encode(rec)
	if err != nil {
		return false, err
	}
	return r.client.SetNX(ctx, r.redisKey(id), ct, ttl).Result()
}

// encode marshals and encrypts a record.
func (r *Redis) encode(rec Record) ([]byte, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return r.cipher.Encrypt(plain)
}

// Load retrieves and decrypts a record by id.
func (r *Redis) Load(ctx context.Context, id string) (Record, bool, error) {
	ct, err := r.client.Get(ctx, r.redisKey(id)).Bytes()
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
	return r.client.Del(ctx, r.redisKey(id)).Err()
}
