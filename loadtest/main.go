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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
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

// counters aggregates the run. All fields are safe for concurrent use: the
// atomics need no external locking, and byCode/latencies are guarded by
// their own mutexes.
type counters struct {
	// total is every HTTP request actually attempted (achieved load).
	total atomic.Int64
	// pairs is every mask+unmask round started (achieved pairs).
	pairs atomic.Int64
	// offeredPairs is every pair the ticker-driven generator tried to
	// enqueue, whether or not the jobs buffer had room (offered load).
	offeredPairs atomic.Int64
	// droppedPairs is offered pairs discarded because the jobs buffer was
	// full — the generator never blocks, so these are lost offered load,
	// not achieved load.
	droppedPairs atomic.Int64
	// badRound counts failed pairs: a failed mask (including the case
	// where mask itself never got a 200), a failed unmask, or a
	// successful unmask whose content didn't match the original.
	badRound atomic.Int64
	// networkErrors counts requests that failed for a real reason
	// (connection refused, per-request timeout, etc.) while the run was
	// still active.
	networkErrors atomic.Int64
	// cancelledAtShutdown counts requests aborted because the run's
	// context was cancelled (duration elapsed / Ctrl-C) — expected
	// shutdown noise, not a network error.
	cancelledAtShutdown atomic.Int64
	// successOK counts requests that returned HTTP 200.
	successOK atomic.Int64

	codeMu sync.Mutex
	byCode map[int]int64

	latMu     sync.Mutex
	maskLat   []time.Duration
	unmaskLat []time.Duration

	start time.Time
	done  time.Time
}

// record stores one sample's outcome under the right counters.
func (c *counters) record(kind string, lat time.Duration, code int, err error, cancelledAtShutdown bool) {
	c.total.Add(1)

	c.codeMu.Lock()
	c.byCode[code]++
	c.codeMu.Unlock()

	switch {
	case cancelledAtShutdown:
		c.cancelledAtShutdown.Add(1)
	case err != nil:
		c.networkErrors.Add(1)
	case code == http.StatusOK:
		c.successOK.Add(1)
	}

	c.latMu.Lock()
	if kind == kindMask {
		c.maskLat = append(c.maskLat, lat)
	} else {
		c.unmaskLat = append(c.unmaskLat, lat)
	}
	c.latMu.Unlock()
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
		retry      = flag.Bool("retry", false, "retry each request up to 3 times (same payload_id) on non-200, emulating the checker")
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
	}
	client := &http.Client{Timeout: *timeout, Transport: transport}

	// Run prefix makes payload ids unique across runs.
	runPrefix := fmt.Sprintf("lt-%d", time.Now().UnixNano())

	c := counters{byCode: make(map[int]int64)}
	c.start = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// Open-model generator: a ticker emits one tick per HTTP request at the
	// target RPS. A pair (mask + unmask) consumes two ticks, so one job is
	// emitted every two ticks. The jobs channel is buffered and the
	// generator uses a non-blocking send, so it never blocks on a busy
	// worker pool: if the buffer is full the pair is dropped and counted,
	// instead of silently throttling the offered load like a blocking send
	// would.
	jobsBuffer := *workers * 4
	if jobsBuffer < 1 {
		jobsBuffer = 1
	}
	jobs := make(chan int, jobsBuffer)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(
				ctx,
				jobs,
				items,
				workerConfig{url: *url, runPrefix: runPrefix, system: *system, apiKey: *apiKey, client: client, retry: *retry},
				&c,
			)
		}()
	}

	// Tick every 5 ms and catch up by elapsed time: a fine-grained ticker
	// silently loses ticks when the generator host is busy, which would
	// lower the offered load.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	// generateJobs is the sole sender on jobs and closes it once ctx is
	// done, so workers (ranging over jobs) drain cleanly and exit on their
	// own — no separate close-from-main step that could race with a send.
	go generateJobs(ctx, ticker, *rps, jobs, &c)

	wg.Wait()
	c.done = time.Now()

	report(&c, *rps, *duration, *url, *dataset, *workers, *retry, *reportPath)
}

// generateJobs emits mask+unmask pairs at rps/2 pairs per second until ctx
// is done, then closes jobs. On every tick it emits as many pairs as the
// elapsed time calls for, so lost ticks never lower the offered load. It
// never blocks: a full buffer means the pair is dropped and counted rather
// than back-pressuring the generator.
func generateJobs(ctx context.Context, ticker *time.Ticker, rps int, jobs chan<- int, c *counters) {
	defer close(jobs)
	start := time.Now()
	seq := int64(0)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// A pair is two HTTP requests.
			due := int64(now.Sub(start).Seconds() * float64(rps) / 2)
			for seq < due {
				seq++
				c.offeredPairs.Add(1)
				select {
				case jobs <- int(seq):
				default:
					c.droppedPairs.Add(1)
				}
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
	retry     bool
}

// worker pulls job indices, runs a mask+unmask round-trip per job and records
// samples. Each job gets a unique payload_id derived from the run prefix and
// the job sequence. worker returns (and stops pulling) once jobs is closed
// and drained.
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
		masked, mCode, mErr := sendWithRetry(ctx, cfg.client, cfg.url, cfg.system, cfg.apiKey, id, item.Text, cfg.retry)
		c.record(kindMask, time.Since(mStart), mCode, mErr, mErr != nil && ctx.Err() != nil)
		if mErr != nil && ctx.Err() != nil {
			// Cut off by the end of the run, not a service failure.
			c.pairs.Add(-1)
			continue
		}
		if mErr != nil || mCode != http.StatusOK {
			// The pair never got a masked payload to unmask: it failed.
			c.badRound.Add(1)
			continue
		}

		// Step 2: unmask with the returned mask; must restore the original.
		uStart := time.Now()
		restored, uCode, uErr := sendWithRetry(ctx, cfg.client, cfg.url, cfg.system, cfg.apiKey, id, masked, cfg.retry)
		c.record(kindUnmask, time.Since(uStart), uCode, uErr, uErr != nil && ctx.Err() != nil)
		if uErr != nil && ctx.Err() != nil {
			c.pairs.Add(-1)
			continue
		}
		ok := uErr == nil && uCode == http.StatusOK && restored == item.Text
		if !ok {
			c.badRound.Add(1)
		}
	}
}

// maxRetryAttempts is the number of attempts (including the first) made per
// request when -retry is set: one initial try plus up to 3 retries.
const maxRetryAttempts = 4

// sendWithRetry sends one /process request, retrying up to 3 additional
// times with the same payload_id on a non-200 response when retry is true —
// emulating the checker's own retry behavior. It stops retrying immediately
// once the run's context is done (shutdown), so it never manufactures extra
// load past the test window.
func sendWithRetry(ctx context.Context, client *http.Client, url, system, apiKey, id, payload string, retry bool) (string, int, error) {
	attempts := 1
	if retry {
		attempts = maxRetryAttempts
	}
	var (
		result string
		code   int
		err    error
	)
	for i := 0; i < attempts; i++ {
		result, code, err = doProcess(ctx, client, url, system, apiKey, id, payload)
		if err == nil && code == http.StatusOK {
			return result, code, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result, code, err
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

// loadDataset reads the jsonl file into items.
func loadDataset(path string) ([]datasetItem, error) {
	f, err := os.Open(safePath(path))
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

// safePath cleans path and rejects any traversal outside the working directory.
func safePath(path string) string {
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		fmt.Fprintf(os.Stderr, "loadtest: unsafe path: %s\n", path)
		os.Exit(1)
	}
	return clean
}

// report prints the summary to stdout and writes the report to the given path
// (or a default location when path is empty). The core sections (target/URL/
// dataset, achieved RPS, totals, error table, 429/bad-round rates, and the
// mask/unmask latency tables) keep their original headings and layout so
// existing reports stay comparable; new sections are appended.
func report(c *counters, targetRPS int, duration time.Duration, url, dataset string, workers int, retry bool, reportPath string) {
	c.latMu.Lock()
	maskLat := append([]time.Duration(nil), c.maskLat...)
	unmaskLat := append([]time.Duration(nil), c.unmaskLat...)
	c.latMu.Unlock()

	elapsed := c.done.Sub(c.start).Seconds()
	achievedRPS := float64(c.total.Load()) / elapsed
	pairsPerSec := float64(c.pairs.Load()) / elapsed

	var b strings.Builder
	fmt.Fprintf(&b, "# Нагрузочный тест pdn-shield\n\n")
	fmt.Fprintf(&b, "- Целевой RPS (запросов/с): %d\n", targetRPS)
	fmt.Fprintf(&b, "- Длительность: %s\n", duration)
	fmt.Fprintf(&b, "- URL process: %s\n", url)
	fmt.Fprintf(&b, "- Датасет: %s\n", dataset)
	fmt.Fprintf(&b, "- Достигнутый RPS (запросов/с): %.2f\n", achievedRPS)
	fmt.Fprintf(&b, "- Пар в секунду: %.2f\n", pairsPerSec)
	fmt.Fprintf(&b, "- Всего запросов: %d\n", c.total.Load())
	fmt.Fprintf(&b, "- Всего пар: %d\n", c.pairs.Load())
	fmt.Fprintf(&b, "- Длительность прогона: %s\n", c.done.Sub(c.start).Round(time.Millisecond))
	fmt.Fprintf(&b, "- keep-alive: MaxIdleConnsPerHost=%d\n", workers)
	fmt.Fprintf(&b, "- retry: %v\n", retry)

	fmt.Fprintf(&b, "\n## Ошибки по кодам\n\n")
	fmt.Fprintf(&b, "| Код | Кол-во |\n|---|---|\n")
	c.codeMu.Lock()
	codes := make([]int, 0, len(c.byCode))
	for code := range c.byCode {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		fmt.Fprintf(&b, "| %d | %d |\n", code, c.byCode[code])
	}
	code429 := c.byCode[http.StatusTooManyRequests]
	c.codeMu.Unlock()

	total := c.total.Load()
	fmt.Fprintf(&b, "\n- Доля 429: %.4f%%\n", pct(code429, total))
	fmt.Fprintf(&b, "- Доля неверных round-trip: %.4f%%\n", pct(c.badRound.Load(), c.pairs.Load()))

	fmt.Fprintf(&b, "\n## Нагрузка: предложено / достигнуто / успешно\n\n")
	offeredRequests := c.offeredPairs.Load() * 2
	droppedRequests := c.droppedPairs.Load() * 2
	offeredRPS := float64(offeredRequests) / duration.Seconds()
	successfulRPS := float64(c.successOK.Load()) / elapsed
	fmt.Fprintf(&b, "| Метрика | Запросов | RPS |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| Предложено (offered) | %d | %.2f |\n", offeredRequests, offeredRPS)
	fmt.Fprintf(&b, "| Достигнуто (achieved, отправлено воркерами) | %d | %.2f |\n", total, achievedRPS)
	fmt.Fprintf(&b, "| Успешно (200 OK) | %d | %.2f |\n", c.successOK.Load(), successfulRPS)
	fmt.Fprintf(&b, "\n- Отброшено генератором (буфер jobs был полон): %d пар (%d запросов)\n", c.droppedPairs.Load(), droppedRequests)
	fmt.Fprintf(&b, "- Сетевые ошибки (не считая отмену при остановке): %d\n", c.networkErrors.Load())
	fmt.Fprintf(&b, "- Отменено при остановке (graceful shutdown, не ошибка): %d\n", c.cancelledAtShutdown.Load())

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
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: write report: %v\n", err)
		return
	}
	fmt.Printf("Отчёт сохранён: %s\n", path)
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
