// Command loadtest drives pdn-shield with an open-model load generator and
// reports latency and correctness. It reproduces the checker contract: pairs
// of POST /process requests sharing one payload_id, the first masking the
// original text and the second restoring it. It is a standalone main in the
// same module and uses only the standard library.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// datasetItem is one line of the jsonl dataset.
type datasetItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Sample kinds.
const (
	kindMask   = "mask"
	kindUnmask = "unmask"
)

// processRequest is the checker contract body.
type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

// processResponse is the checker contract response.
type processResponse struct {
	Result string `json:"result"`
}

// sample is one measured request.
type sample struct {
	kind string // "mask" or "unmask"
	lat  time.Duration
	code int
	ok   bool // round-trip correctness for unmask
}

// counters aggregates the run.
type counters struct {
	total       atomic.Int64
	pairs       atomic.Int64
	byCode      sync.Map // code -> int64
	badRound    atomic.Int64
	latencies   []sample
	mu          sync.Mutex
	start       time.Time
	done        time.Time
	reportedRPS float64
}

func main() {
	var (
		url        = flag.String("url", "http://localhost:8080/process", "URL of the /process endpoint")
		rps        = flag.Int("rps", 1000, "target requests per second")
		duration   = flag.Duration("duration", 5*time.Minute, "test duration")
		workers    = flag.Int("workers", 256, "number of concurrent workers")
		dataset    = flag.String("dataset", "internal/pii/testdata/dataset.jsonl", "path to jsonl dataset")
		timeout    = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		system     = flag.String("system", "", "X-System-Id header; empty means the default checker system")
		apiKey     = flag.String("api-key", "", "X-API-Key header; empty means no key")
		reportPath = flag.String("report", "", "path to write the report; default ./loadtest-report-<ts>.md")
		insecure   = flag.Bool("insecure", false, "skip TLS certificate verification")
	)
	flag.Parse()

	items, err := loadDataset(*dataset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: dataset: %v\n", err)
		os.Exit(1)
	}
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "loadtest: dataset is empty\n")
		os.Exit(1)
	}

	transport := &http.Transport{
		MaxIdleConns:        *workers * 2,
		MaxIdleConnsPerHost: *workers,
		MaxConnsPerHost:     *workers,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
	}
	client := &http.Client{Timeout: *timeout, Transport: transport}

	// Run prefix makes payload ids unique across runs.
	runPrefix := fmt.Sprintf("lt-%d", time.Now().UnixNano())

	var c counters
	c.start = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// Worker pool.
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, jobs, items, workerConfig{url: *url, runPrefix: runPrefix, system: *system, apiKey: *apiKey, client: client}, &c)
		}()
	}

	// Open-model generator: a ticker emits one tick per HTTP request at the
	// target RPS. A pair (mask + unmask) consumes two ticks, so one job is
	// emitted every two ticks. Workers pull from the pool, so the generator
	// never blocks on the service.
	interval := time.Second / time.Duration(*rps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	genDone := make(chan struct{})
	go generateJobs(ctx, ticker, jobs, genDone)

	<-ctx.Done()
	close(jobs)
	wg.Wait()
	<-genDone

	c.done = time.Now()
	c.reportedRPS = float64(c.total.Load()) / c.done.Sub(c.start).Seconds()

	report(&c, *rps, *duration, *url, *dataset, *workers, *reportPath)
}

// generateJobs emits one job every two ticks (a mask+unmask pair) until ctx is
// done, then closes genDone.
func generateJobs(ctx context.Context, ticker *time.Ticker, jobs chan<- int, genDone chan<- struct{}) {
	defer close(genDone)
	seq := int64(0)
	ticks := int64(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ticks++
			// A pair is two HTTP requests = two ticks.
			if ticks%2 != 0 {
				continue
			}
			seq++
			select {
			case jobs <- int(seq):
			case <-ctx.Done():
				return
			}
		}
	}
}

// workerConfig bundles the shared request configuration for workers.
type workerConfig struct {
	url       string
	runPrefix string
	system    string
	apiKey    string
	client    *http.Client
}

// worker pulls job indices, runs a mask+unmask round-trip per job and records
// samples. Each job gets a unique payload_id derived from the run prefix and
// the job sequence.
func worker(ctx context.Context, jobs <-chan int, items []datasetItem, cfg workerConfig, c *counters) {
	for seq := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		item := items[int(time.Now().UnixNano())%len(items)]
		id := fmt.Sprintf("%s-%d", cfg.runPrefix, seq)
		c.pairs.Add(1)

		// Step 1: mask the original text.
		mStart := time.Now()
		masked, mCode, err := doProcess(ctx, cfg.client, cfg.url, cfg.system, cfg.apiKey, id, item.Text)
		c.record(sample{kind: kindMask, lat: time.Since(mStart), code: mCode})
		if err != nil || mCode != http.StatusOK {
			continue
		}

		// Step 2: unmask with the returned mask; must restore the original.
		uStart := time.Now()
		restored, uCode, err := doProcess(ctx, cfg.client, cfg.url, cfg.system, cfg.apiKey, id, masked)
		ok := err == nil && uCode == http.StatusOK && restored == item.Text
		c.record(sample{kind: kindUnmask, lat: time.Since(uStart), code: uCode, ok: ok})
		if !ok {
			c.badRound.Add(1)
		}
	}
}

// doProcess sends one /process request and returns the result field.
func doProcess(ctx context.Context, client *http.Client, url, system, apiKey, id, payload string) (string, int, error) {
	body, _ := json.Marshal(processRequest{Payload: payload, PayloadID: id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if system != "" {
		req.Header.Set("X-System-Id", system)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, nil
	}
	var pr processResponse
	if err := json.Unmarshal(data, &pr); err != nil {
		return "", resp.StatusCode, err
	}
	return pr.Result, resp.StatusCode, nil
}

// record stores a sample and bumps counters.
func (c *counters) record(s sample) {
	c.total.Add(1)
	if v, ok := c.byCode.Load(s.code); ok {
		v.(*atomic.Int64).Add(1)
	} else {
		n := &atomic.Int64{}
		n.Add(1)
		c.byCode.Store(s.code, n)
	}
	c.mu.Lock()
	c.latencies = append(c.latencies, s)
	c.mu.Unlock()
}

// loadDataset reads the jsonl file into items.
func loadDataset(path string) ([]datasetItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var items []datasetItem
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var it datasetItem
		if err := json.Unmarshal([]byte(line), &it); err != nil {
			return nil, fmt.Errorf("line: %w", err)
		}
		items = append(items, it)
	}
	return items, sc.Err()
}

// report prints the summary to stdout and writes the report to the given path
// (or a default location when path is empty).
func report(c *counters, targetRPS int, duration time.Duration, url, dataset string, workers int, reportPath string) {
	c.mu.Lock()
	samples := c.latencies
	c.mu.Unlock()

	maskLat := latenciesFor(samples, kindMask)
	unmaskLat := latenciesFor(samples, kindUnmask)

	elapsed := c.done.Sub(c.start).Seconds()
	pairsPerSec := float64(c.pairs.Load()) / elapsed

	var b strings.Builder
	fmt.Fprintf(&b, "# Нагрузочный тест pdn-shield\n\n")
	fmt.Fprintf(&b, "- Целевой RPS (запросов/с): %d\n", targetRPS)
	fmt.Fprintf(&b, "- Длительность: %s\n", duration)
	fmt.Fprintf(&b, "- URL process: %s\n", url)
	fmt.Fprintf(&b, "- Датасет: %s\n", dataset)
	fmt.Fprintf(&b, "- Достигнутый RPS (запросов/с): %.2f\n", c.reportedRPS)
	fmt.Fprintf(&b, "- Пар в секунду: %.2f\n", pairsPerSec)
	fmt.Fprintf(&b, "- Всего запросов: %d\n", c.total.Load())
	fmt.Fprintf(&b, "- Всего пар: %d\n", c.pairs.Load())
	fmt.Fprintf(&b, "- Длительность прогона: %s\n", c.done.Sub(c.start).Round(time.Millisecond))
	fmt.Fprintf(&b, "- keep-alive: MaxIdleConnsPerHost=%d\n", workers)
	fmt.Fprintf(&b, "\n## Ошибки по кодам\n\n")
	fmt.Fprintf(&b, "| Код | Кол-во |\n|---|---|\n")
	c.byCode.Range(func(k, v interface{}) bool {
		fmt.Fprintf(&b, "| %d | %d |\n", k, v.(*atomic.Int64).Load())
		return true
	})
	total := c.total.Load()
	code429 := int64(0)
	if v, ok := c.byCode.Load(http.StatusTooManyRequests); ok {
		code429 = v.(*atomic.Int64).Load()
	}
	fmt.Fprintf(&b, "\n- Доля 429: %.4f%%\n", pct(code429, total))
	fmt.Fprintf(&b, "- Доля неверных round-trip: %.4f%%\n", pct(c.badRound.Load(), total))

	fmt.Fprintf(&b, "\n## Латентность mask\n\n")
	writeLatency(&b, maskLat)
	fmt.Fprintf(&b, "\n## Латентность unmask\n\n")
	writeLatency(&b, unmaskLat)

	fmt.Println(b.String())

	ts := time.Now().Format("20060102-150405")
	path := reportPath
	if path == "" {
		path = fmt.Sprintf("./loadtest-report-%s.md", ts)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: write report: %v\n", err)
		return
	}
	fmt.Printf("Отчёт сохранён: %s\n", path)
}

func latenciesFor(samples []sample, kind string) []time.Duration {
	var out []time.Duration
	for _, s := range samples {
		if s.kind == kind {
			out = append(out, s.lat)
		}
	}
	return out
}

func writeLatency(b *strings.Builder, lat []time.Duration) {
	if len(lat) == 0 {
		fmt.Fprintf(b, "Нет данных\n")
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	fmt.Fprintf(b, "| Метрика | Значение |\n|---|---|\n")
	fmt.Fprintf(b, "| p50 | %s |\n", percentile(lat, 0.50))
	fmt.Fprintf(b, "| p90 | %s |\n", percentile(lat, 0.90))
	fmt.Fprintf(b, "| p95 | %s |\n", percentile(lat, 0.95))
	fmt.Fprintf(b, "| p99 | %s |\n", percentile(lat, 0.99))
	fmt.Fprintf(b, "| max | %s |\n", lat[len(lat)-1])
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
