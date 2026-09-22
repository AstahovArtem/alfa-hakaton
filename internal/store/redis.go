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

// Redis is a Store backed by a Redis server using a minimal RESP2 client.
type Redis struct {
	addr     string
	password string
	pool     chan net.Conn
	cipher   *crypto.Cipher
	timeout  time.Duration
}

// NewRedis creates a Redis store. key must be 32 bytes. poolSize is the number
// of pooled connections.
func NewRedis(addr, password string, key []byte, poolSize int) (*Redis, error) {
	c, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	if poolSize <= 0 {
		poolSize = 32
	}
	r := &Redis{
		addr:     addr,
		password: password,
		pool:     make(chan net.Conn, poolSize),
		cipher:   c,
		timeout:  200 * time.Millisecond,
	}
	// Pre-warm the pool.
	for i := 0; i < poolSize; i++ {
		conn, err := r.dial()
		if err != nil {
			// Non-fatal: connections are created lazily on demand.
			continue
		}
		r.pool <- conn
	}
	return r, nil
}

func (r *Redis) dial() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", r.addr, r.timeout)
	if err != nil {
		return nil, err
	}
	if r.password != "" {
		if err := r.writeCommand(conn, "AUTH", r.password); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := r.readReply(conn); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// getConn returns a pooled connection or dials a new one.
func (r *Redis) getConn() (net.Conn, error) {
	select {
	case conn := <-r.pool:
		return conn, nil
	default:
		return r.dial()
	}
}

func (r *Redis) putConn(conn net.Conn) {
	select {
	case r.pool <- conn:
	default:
		conn.Close()
	}
}

// withConn runs fn with a connection, returning it to the pool on success and
// closing it on error.
func (r *Redis) withConn(fn func(conn net.Conn) error) error {
	conn, err := r.getConn()
	if err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		conn.Close()
		return err
	}
	r.putConn(conn)
	return nil
}

// Ping checks connectivity.
func (r *Redis) Ping(ctx context.Context) error {
	return r.withConn(func(conn net.Conn) error {
		if err := r.writeCommand(conn, "PING"); err != nil {
			return err
		}
		_, err := r.readReply(conn)
		return err
	})
}

// Close closes all pooled connections.
func (r *Redis) Close() {
	for {
		select {
		case conn := <-r.pool:
			conn.Close()
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
	return r.withConn(func(conn net.Conn) error {
		if err := r.writeCommand(conn, "SET", id, string(ct), "EX", strconv.FormatInt(ttlSec, 10)); err != nil {
			return err
		}
		_, err := r.readReply(conn)
		return err
	})
}

// Load retrieves and decrypts a record by id.
func (r *Redis) Load(ctx context.Context, id string) (Record, bool, error) {
	var ct string
	err := r.withConn(func(conn net.Conn) error {
		if err := r.writeCommand(conn, "GET", id); err != nil {
			return err
		}
		reply, err := r.readReply(conn)
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
	return r.withConn(func(conn net.Conn) error {
		if err := r.writeCommand(conn, "DEL", id); err != nil {
			return err
		}
		_, err := r.readReply(conn)
		return err
	})
}

// writeCommand writes a RESP2 array command.
func (r *Redis) writeCommand(conn net.Conn, args ...string) error {
	conn.SetDeadline(time.Now().Add(r.timeout))
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
	_, err := conn.Write(b)
	return err
}

// readReply reads a single RESP2 reply.
func (r *Redis) readReply(conn net.Conn) (interface{}, error) {
	conn.SetDeadline(time.Now().Add(r.timeout))
	br := bufio.NewReader(conn)
	return readRESP(br)
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
