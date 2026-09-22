package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"pdn-shield/internal/crypto"
)

// Default pool and timeout values used when the caller does not override them.
const (
	DefaultRedisPoolSize  = 64
	DefaultRedisWait      = 500 * time.Millisecond
	DefaultRedisTimeout   = 500 * time.Millisecond
	DefaultRedisDial      = time.Second
	redisIdlePingInterval = 60 * time.Second
)

// redisConn is a pooled connection with its reusable buffered reader.
type redisConn struct {
	conn   net.Conn
	reader *bufio.Reader
	// lastUsed is the wall-clock time the connection was last returned to the
	// pool. It drives the idle health-check PING.
	lastUsed time.Time
}

// Redis is a Store backed by a Redis server using a minimal RESP2 client.
type Redis struct {
	addr     string
	password string
	// pool holds idle connections. Its capacity is the pool size.
	pool chan *redisConn
	// sem is the live-connection budget. Acquiring it grants the right to dial
	// one more connection; releasing it frees that budget.
	sem     chan struct{}
	cipher  *crypto.Cipher
	timeout time.Duration
	dialTO  time.Duration
	waitTO  time.Duration
}

// Options configures the Redis client pool.
type Options struct {
	PoolSize int
	// Wait is the maximum time to wait for a free connection when the pool is
	// exhausted. Zero means DefaultRedisWait.
	Wait time.Duration
	// Timeout is the read/write deadline for a single command. Zero means
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
	r := &Redis{
		addr:     addr,
		password: password,
		pool:     make(chan *redisConn, opt.PoolSize),
		sem:      make(chan struct{}, opt.PoolSize),
		cipher:   c,
		timeout:  opt.Timeout,
		dialTO:   opt.Dial,
		waitTO:   opt.Wait,
	}
	return r, nil
}

// dial opens a new connection and authenticates if a password is set.
func (r *Redis) dial() (*redisConn, error) {
	conn, err := net.DialTimeout("tcp", r.addr, r.dialTO)
	if err != nil {
		return nil, err
	}
	rc := &redisConn{conn: conn, reader: bufio.NewReader(conn), lastUsed: time.Now()}
	if r.password != "" {
		if err := r.writeCommand(rc, "AUTH", r.password); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := r.readReply(rc); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return rc, nil
}

// getConn returns a pooled connection, dialing lazily up to the pool limit and
// otherwise waiting for a free connection until ctx is done or the wait
// timeout elapses.
func (r *Redis) getConn(ctx context.Context) (*redisConn, error) {
	// 1. Reuse an idle connection if one is available.
	select {
	case rc := <-r.pool:
		return r.healthCheck(rc)
	default:
	}

	// 2. Try to acquire the budget to dial a new connection.
	select {
	case r.sem <- struct{}{}:
		rc, err := r.dial()
		if err != nil {
			<-r.sem
			return r.waitConn(ctx)
		}
		return rc, nil
	default:
	}

	// 3. Pool exhausted: wait for an idle connection or budget.
	return r.waitConn(ctx)
}

// waitConn waits for a free connection or dial budget until ctx is done or the
// wait timeout elapses.
func (r *Redis) waitConn(ctx context.Context) (*redisConn, error) {
	timer := time.NewTimer(r.waitTO)
	defer timer.Stop()
	for {
		select {
		case rc := <-r.pool:
			return r.healthCheck(rc)
		case r.sem <- struct{}{}:
			rc, err := r.dial()
			if err != nil {
				<-r.sem
				continue
			}
			return rc, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("redis: pool exhausted: no free connection within wait timeout")
		}
	}
}

// healthCheck pings connections that have been idle too long, replacing them
// on failure. The caller already holds the connection's budget, so a fresh
// connection is dialed without changing the budget.
func (r *Redis) healthCheck(rc *redisConn) (*redisConn, error) {
	if time.Since(rc.lastUsed) <= redisIdlePingInterval {
		return rc, nil
	}
	if err := r.pingConn(rc); err == nil {
		return rc, nil
	}
	rc.conn.Close()
	fresh, err := r.dial()
	if err != nil {
		return nil, err
	}
	return fresh, nil
}

// putConn returns a connection to the pool. The connection's budget is kept
// until the connection is closed.
func (r *Redis) putConn(rc *redisConn) {
	rc.lastUsed = time.Now()
	r.pool <- rc
}

// closeConn closes a connection and releases its budget.
func (r *Redis) closeConn(rc *redisConn) {
	rc.conn.Close()
	<-r.sem
}

// withConn runs fn with a connection, returning it to the pool on success and
// closing it on error.
func (r *Redis) withConn(ctx context.Context, fn func(rc *redisConn) error) error {
	rc, err := r.getConn(ctx)
	if err != nil {
		return err
	}
	if err := fn(rc); err != nil {
		r.closeConn(rc)
		return err
	}
	r.putConn(rc)
	return nil
}

// pingConn sends a PING and reads the reply, returning any error.
func (r *Redis) pingConn(rc *redisConn) error {
	if err := r.writeCommand(rc, "PING"); err != nil {
		return err
	}
	_, err := r.readReply(rc)
	return err
}

// Ping checks connectivity.
func (r *Redis) Ping(ctx context.Context) error {
	return r.withConn(ctx, func(rc *redisConn) error {
		return r.pingConn(rc)
	})
}

// Close closes all pooled connections.
func (r *Redis) Close() {
	for {
		select {
		case rc := <-r.pool:
			rc.conn.Close()
		default:
			return
		}
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
	ttlSec := int64(ttl / time.Second)
	if ttlSec <= 0 {
		ttlSec = 0
	}
	return r.withConn(ctx, func(rc *redisConn) error {
		if err := r.writeCommand(rc, "SET", id, string(ct), "EX", strconv.FormatInt(ttlSec, 10)); err != nil {
			return err
		}
		_, err := r.readReply(rc)
		return err
	})
}

// Load retrieves and decrypts a record by id.
func (r *Redis) Load(ctx context.Context, id string) (Record, bool, error) {
	var ct string
	err := r.withConn(ctx, func(rc *redisConn) error {
		if err := r.writeCommand(rc, "GET", id); err != nil {
			return err
		}
		reply, err := r.readReply(rc)
		if err != nil {
			return err
		}
		if reply == nil {
			ct = ""
			return nil
		}
		s, ok := reply.(string)
		if !ok {
			return errors.New("redis: unexpected GET reply type")
		}
		ct = s
		return nil
	})
	if err != nil {
		return Record{}, false, err
	}
	if ct == "" {
		return Record{}, false, nil
	}
	plain, err := r.cipher.Decrypt([]byte(ct))
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
	return r.withConn(ctx, func(rc *redisConn) error {
		if err := r.writeCommand(rc, "DEL", id); err != nil {
			return err
		}
		_, err := r.readReply(rc)
		return err
	})
}

// writeCommand writes a RESP2 array command.
func (r *Redis) writeCommand(rc *redisConn, args ...string) error {
	rc.conn.SetDeadline(time.Now().Add(r.timeout))
	var b []byte
	b = append(b, '*')
	b = strconv.AppendInt(b, int64(len(args)), 10)
	b = append(b, '\r', '\n')
	for _, a := range args {
		b = append(b, '$')
		b = strconv.AppendInt(b, int64(len(a)), 10)
		b = append(b, '\r', '\n')
		b = append(b, a...)
		b = append(b, '\r', '\n')
	}
	_, err := rc.conn.Write(b)
	return err
}

// readReply reads a single RESP2 reply, reusing the connection's reader.
func (r *Redis) readReply(rc *redisConn) (interface{}, error) {
	rc.conn.SetDeadline(time.Now().Add(r.timeout))
	return readRESP(rc.reader)
}

func readRESP(br *bufio.Reader) (interface{}, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, errors.New("redis: short reply line")
	}
	prefix := line[0]
	body := line[1 : len(line)-2] // strip \r\n
	switch prefix {
	case '+', '-':
		if prefix == '-' {
			return nil, errors.New("redis: " + body)
		}
		return body, nil
	case ':':
		n, err := strconv.ParseInt(body, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := readFull(br, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]interface{}, n)
		for i := 0; i < n; i++ {
			v, err := readRESP(br)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("redis: unknown reply prefix %q", prefix)
	}
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
