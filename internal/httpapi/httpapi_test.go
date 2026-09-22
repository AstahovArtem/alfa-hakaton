package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"pdn-shield/internal/config"
	"pdn-shield/internal/engine"
	"pdn-shield/internal/mask"
	"pdn-shield/internal/metrics"
	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
	"pdn-shield/internal/store"
)

const testText = "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67"

// checkerHeaders identifies the checker system for non-process endpoints.
func checkerHeaders() map[string]string {
	return map[string]string{"X-System-Id": "checker"}
}

func testConfig() *config.Config {
	return &config.Config{
		Server: config.Server{
			Addr:          ":0",
			MaxBodyBytes:  1 << 20,
			MaxInflight:   512,
			DefaultSystem: "checker",
		},
		Store: config.Store{Kind: "memory", TTL: time.Hour},
		LLM:   config.LLM{BaseURL: "http://unused", Model: "test-model", Timeout: 5 * time.Second},
		Systems: []config.System{
			{ID: "checker", Enabled: true, Strategy: "partial", Unmask: true},
			{
				ID:                    "demo",
				Enabled:               true,
				APIKeyEnv:             "PDN_DEMO_KEY",
				Strategy:              "partial",
				AllowStrategyOverride: true,
				Unmask:                true,
			},
			{ID: "chatbot", Enabled: true, APIKeyEnv: "PDN_CHATBOT_KEY", Strategy: "token", Unmask: false},
			{ID: "legacy_crm", Enabled: false, APIKeyEnv: "PDN_LEGACY_KEY"},
		},
	}
}

func testServer(t *testing.T, cfg *config.Config) (*Server, *httptest.Server) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st, err := store.NewMemory(key)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(st.Close)
	p := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		"partial":   mask.MustPartial(),
		"full":      mask.NewFull(),
		"token":     mask.NewToken(),
		"synthetic": mask.NewSynthetic(),
	}
	eng := engine.New(p, st, strategies)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	s := New(cfg, eng, st, m, logger)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

// newMemoryStore builds an in-memory store with a fixed key.
func newMemoryStore(key []byte) (*store.Memory, error) {
	return store.NewMemory(key)
}

// newServerWithLogger builds a Server with the given store and logger.
func newServerWithLogger(cfg *config.Config, st store.Store, logger *slog.Logger) *Server {
	p := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		"partial":   mask.MustPartial(),
		"full":      mask.NewFull(),
		"token":     mask.NewToken(),
		"synthetic": mask.NewSynthetic(),
	}
	eng := engine.New(p, st, strategies)
	m := metrics.New()
	return New(cfg, eng, st, m, logger)
}

func doJSON(
	t *testing.T,
	ts *httptest.Server,
	method, path string,
	headers map[string]string,
	body interface{},
) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(headerContentType, "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, data
}

func TestProcessMaskThenUnmask(t *testing.T) {
	_, ts := testServer(t, testConfig())

	mres := maskAndVerify(t, ts)
	verifyIdempotency(t, ts, mres.Result)
	unmaskAndVerify(t, ts, mres.Result)
}

// maskAndVerify masks testText and verifies the result hides PII.
func maskAndVerify(t *testing.T, ts *httptest.Server) processResponse {
	t.Helper()
	resp, data := doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    testText,
		"payload_id": "doc1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("mask status = %d, body %s", resp.StatusCode, data)
	}
	var mres processResponse
	if err := json.Unmarshal(data, &mres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if mres.Result == testText {
		t.Errorf("masked result equals original")
	}
	if strings.Contains(mres.Result, "Иванов") || strings.Contains(mres.Result, "4509") {
		t.Errorf("masked result leaks PII: %q", mres.Result)
	}
	return mres
}

// verifyIdempotency checks that repeated mask requests return the same result.
func verifyIdempotency(t *testing.T, ts *httptest.Server, first string) {
	t.Helper()
	var lastResult string
	for i := 0; i < 3; i++ {
		resp2, data2 := doJSON(t, ts, "POST", "/process", nil, map[string]string{
			"payload":    testText,
			"payload_id": "doc1",
		})
		if resp2.StatusCode != 200 {
			t.Fatalf("mask2 status = %d", resp2.StatusCode)
		}
		var mres2 processResponse
		if err := json.Unmarshal(data2, &mres2); err != nil {
			t.Fatalf("unmarshal2: %v", err)
		}
		if i > 0 && mres2.Result != lastResult {
			t.Errorf("idempotency failed on iteration %d: %q vs %q", i, mres2.Result, lastResult)
		}
		lastResult = mres2.Result
	}
	if lastResult != first {
		t.Errorf("idempotency failed: %q vs %q", lastResult, first)
	}
}

// unmaskAndVerify sends the masked text as payload and verifies the original is
// restored.
func unmaskAndVerify(t *testing.T, ts *httptest.Server, masked string) {
	t.Helper()
	resp3, data3 := doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    masked,
		"payload_id": "doc1",
	})
	if resp3.StatusCode != 200 {
		t.Fatalf("unmask status = %d, body %s", resp3.StatusCode, data3)
	}
	var ures processResponse
	if err := json.Unmarshal(data3, &ures); err != nil {
		t.Fatalf("unmarshal3: %v", err)
	}
	if ures.Result != testText {
		t.Errorf("unmask result = %q, want %q", ures.Result, testText)
	}
}

func TestProcessInvalidJSON(t *testing.T) {
	_, ts := testServer(t, testConfig())
	req, _ := http.NewRequest("POST", ts.URL+"/process", strings.NewReader("not json"))
	req.Header.Set(headerContentType, "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProcessUnknownPayloadReturnsAsIs(t *testing.T) {
	_, ts := testServer(t, testConfig())
	// Mask once to register the id.
	doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    testText,
		"payload_id": "docX",
	})
	// Send a payload that matches neither the original nor the mask.
	resp, data := doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    "совершенно другой текст",
		"payload_id": "docX",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200, body %s", resp.StatusCode, data)
	}
	var pres processResponse
	if err := json.Unmarshal(data, &pres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pres.Result != "совершенно другой текст" {
		t.Errorf("result = %q, want payload as-is", pres.Result)
	}
}

func TestProcessEmptyPayload(t *testing.T) {
	_, ts := testServer(t, testConfig())
	// Empty payload with a valid id is allowed and returns an empty result.
	resp, data := doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    "",
		"payload_id": "x",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200, body %s", resp.StatusCode, data)
	}
	var pres processResponse
	if err := json.Unmarshal(data, &pres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pres.Result != "" {
		t.Errorf("result = %q, want empty", pres.Result)
	}
}

func TestProcessMissingPayloadID(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, _ := doJSON(t, ts, "POST", "/process", nil, map[string]string{"payload": "", "payload_id": ""})
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthForbidden(t *testing.T) {
	_, ts := testServer(t, testConfig())
	// Unknown system.
	resp, _ := doJSON(t, ts, "POST", "/mask", map[string]string{"X-System-Id": "nope"}, map[string]string{"text": "x"})
	if resp.StatusCode != 403 {
		t.Errorf("unknown system status = %d, want 403", resp.StatusCode)
	}
	// Disabled system.
	resp, _ = doJSON(
		t,
		ts,
		"POST",
		"/mask",
		map[string]string{"X-System-Id": "legacy_crm"},
		map[string]string{"text": "x"},
	)
	if resp.StatusCode != 403 {
		t.Errorf("disabled system status = %d, want 403", resp.StatusCode)
	}
}

func TestAuthUnauthorized(t *testing.T) {
	os.Setenv("PDN_DEMO_KEY", "secret-key")
	defer os.Unsetenv("PDN_DEMO_KEY")
	_, ts := testServer(t, testConfig())
	resp, _ := doJSON(t, ts, "POST", "/mask", map[string]string{
		"X-System-Id": "demo",
		"X-API-Key":   "wrong",
	}, map[string]string{"text": "x"})
	if resp.StatusCode != 401 {
		t.Errorf("wrong key status = %d, want 401", resp.StatusCode)
	}
	resp, _ = doJSON(t, ts, "POST", "/mask", map[string]string{
		"X-System-Id": "demo",
		"X-API-Key":   "secret-key",
	}, map[string]string{"text": "x"})
	if resp.StatusCode != 200 {
		t.Errorf("correct key status = %d, want 200", resp.StatusCode)
	}
}

func TestMaskEndpoint(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": testText})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body %s", resp.StatusCode, data)
	}
	var mres maskResponse
	if err := json.Unmarshal(data, &mres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if mres.ID == "" {
		t.Errorf("id is empty")
	}
	if mres.Found["full_name"] != 1 || mres.Found["passport"] != 1 || mres.Found["phone"] != 1 {
		t.Errorf("found = %v", mres.Found)
	}
	if strings.Contains(mres.Masked, "Иванов") {
		t.Errorf("masked leaks PII: %q", mres.Masked)
	}
}

func TestUnmaskDisabledForSystem(t *testing.T) {
	os.Setenv("PDN_CHATBOT_KEY", "chatbot-key")
	defer os.Unsetenv("PDN_CHATBOT_KEY")
	_, ts := testServer(t, testConfig())
	resp, _ := doJSON(t, ts, "POST", "/unmask", map[string]string{
		"X-System-Id": "chatbot",
		"X-API-Key":   "chatbot-key",
	}, map[string]string{"id": "x", "text": "y"})
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestUnmaskRoundTrip(t *testing.T) {
	_, ts := testServer(t, testConfig())
	_, data := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": testText})
	var mres maskResponse
	if err := json.Unmarshal(data, &mres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp, data := doJSON(
		t,
		ts,
		"POST",
		"/unmask",
		checkerHeaders(),
		map[string]string{"id": mres.ID, "text": mres.Masked},
	)
	if resp.StatusCode != 200 {
		t.Fatalf("unmask status = %d, body %s", resp.StatusCode, data)
	}
	var ures unmaskResponse
	if err := json.Unmarshal(data, &ures); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ures.Text != testText {
		t.Errorf("unmask = %q, want %q", ures.Text, testText)
	}
	if ures.Misses != 0 {
		t.Errorf("misses = %d", ures.Misses)
	}
}

func TestHealthz(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "GET", "/healthz", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(data), `"status":"ok"`) {
		t.Errorf("healthz body = %s", data)
	}
}

func TestReadyz(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, _ := doJSON(t, ts, "GET", "/readyz", nil, nil)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestBodyTooLarge(t *testing.T) {
	cfg := testConfig()
	cfg.Server.MaxBodyBytes = 100
	_, ts := testServer(t, cfg)
	big := strings.Repeat("a", 1000)
	resp, _ := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": big})
	if resp.StatusCode != 413 {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

func TestInflightLimit(t *testing.T) {
	cfg := testConfig()
	cfg.Server.MaxInflight = 1
	s, ts := testServer(t, cfg)

	// Fill the semaphore directly to simulate a full inflight slot.
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	resp, data := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": "x"})
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want 429, body %s", resp.StatusCode, data)
	}
	if resp.Header.Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", resp.Header.Get("Retry-After"))
	}
}

func TestMetricsEndpoint(t *testing.T) {
	_, ts := testServer(t, testConfig())
	// Generate some traffic so the counters are registered.
	doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": testText})
	resp, data := doJSON(t, ts, "GET", "/metrics", checkerHeaders(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(data), "pdn_requests_total") {
		t.Errorf("metrics missing pdn_requests_total")
	}
	if !strings.Contains(string(data), "pdn_pii_found_total") {
		t.Errorf("metrics missing pdn_pii_found_total")
	}
}

func TestIndexPage(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "GET", "/", checkerHeaders(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(data), "pdn-shield") {
		t.Errorf("index page missing title")
	}
}

func TestRequestLogStageTimings(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := testConfig()
	st, err := store.NewMemory(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(st.Close)
	s := newServerWithLogger(cfg, st, logger)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, _ := doJSON(t, ts, "POST", "/process", nil, map[string]string{
		"payload":    testText,
		"payload_id": "doc1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	out := buf.String()
	for _, field := range []string{"detect_ms", "mask_ms", "store_ms"} {
		if !strings.Contains(out, field) {
			t.Errorf("request log missing %s", field)
		}
	}
	if strings.Contains(out, "llm_ms") {
		t.Errorf("request log should not contain llm_ms for /process")
	}
	if strings.Contains(out, "Иванов") || strings.Contains(out, "4509") {
		t.Errorf("request log leaks PII")
	}
}

func TestMaskStrategyOverrideAllowed(t *testing.T) {
	os.Setenv("PDN_DEMO_KEY", "demo-key")
	defer os.Unsetenv("PDN_DEMO_KEY")
	_, ts := testServer(t, testConfig())
	headers := map[string]string{"X-System-Id": "demo", "X-API-Key": "demo-key"}
	resp, data := doJSON(t, ts, "POST", "/mask", headers, map[string]string{
		"text":     testText,
		"strategy": "full",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body %s", resp.StatusCode, data)
	}
	var mres maskResponse
	if err := json.Unmarshal(data, &mres); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if mres.Strategy != "full" {
		t.Errorf("strategy = %q, want full", mres.Strategy)
	}
	if strings.Contains(mres.Masked, "Иванов") || strings.Contains(mres.Masked, "4509") {
		t.Errorf("masked leaks PII: %q", mres.Masked)
	}
}

func TestMaskStrategyOverrideDenied(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{
		"text":     testText,
		"strategy": "full",
	})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403, body %s", resp.StatusCode, data)
	}
	if !strings.Contains(string(data), "strategy override not allowed") {
		t.Errorf("body = %s", data)
	}
}

func TestMaskStrategyOverrideUnknown(t *testing.T) {
	os.Setenv("PDN_DEMO_KEY", "demo-key")
	defer os.Unsetenv("PDN_DEMO_KEY")
	_, ts := testServer(t, testConfig())
	headers := map[string]string{"X-System-Id": "demo", "X-API-Key": "demo-key"}
	resp, data := doJSON(t, ts, "POST", "/mask", headers, map[string]string{
		"text":     testText,
		"strategy": "bogus",
	})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400, body %s", resp.StatusCode, data)
	}
	if !strings.Contains(string(data), "unknown strategy") {
		t.Errorf("body = %s", data)
	}
}

func TestChatProxyStrategyOverride(t *testing.T) {
	var captured []byte
	llm := fakeLLM(t, &captured)
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	// checker is not allowed to override.
	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", checkerHeaders(), map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
		"strategy": "full",
	})
	if resp.StatusCode != 403 {
		t.Fatalf("denied status = %d, want 403, body %s", resp.StatusCode, data)
	}

	// demo is allowed; the strategy field must not reach the LLM.
	os.Setenv("PDN_DEMO_KEY", "demo-key")
	defer os.Unsetenv("PDN_DEMO_KEY")
	headers := map[string]string{"X-System-Id": "demo", "X-API-Key": "demo-key"}
	resp, data = doJSON(t, ts, "POST", "/v1/chat/completions", headers, map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
		"strategy": "full",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("allowed status = %d, body %s", resp.StatusCode, data)
	}
	if bytes.Contains(captured, []byte("strategy")) {
		t.Errorf("strategy field leaked to LLM: %s", captured)
	}
	if bytes.Contains(captured, []byte("Иванов")) || bytes.Contains(captured, []byte("4509")) {
		t.Errorf("LLM request leaked PII: %s", captured)
	}
}
