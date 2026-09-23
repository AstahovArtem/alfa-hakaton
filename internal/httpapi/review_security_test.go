package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- A1: keyless systems restricted to POST /process ------------------------

// TestKeylessSystemRestrictedToProcess verifies that checker (a keyless
// system: api_key and api_key_env both empty) is rejected with 403 on every
// route except POST /process, even when its id is sent explicitly via
// X-System-Id.
func TestKeylessSystemRestrictedToProcess(t *testing.T) {
	_, ts := testServer(t, testConfig())
	headers := map[string]string{"X-System-Id": "checker"}

	cases := []struct {
		method, path string
		body         interface{}
	}{
		{"POST", "/mask", map[string]string{"text": "x"}},
		{"POST", "/unmask", map[string]string{"id": "x", "text": "y"}},
		{"POST", "/v1/chat/completions", map[string]interface{}{"messages": []map[string]string{{"role": "user", "content": "x"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, data := doJSON(t, ts, tc.method, tc.path, headers, tc.body)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403, body %s", resp.StatusCode, data)
			}
		})
	}

	// POST /process must still work for the keyless system.
	resp, data := doJSON(t, ts, "POST", "/process", headers, map[string]string{
		"payload": "x", "payload_id": "keyless1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/process status = %d, want 200, body %s", resp.StatusCode, data)
	}
}

// TestKeylessSystemRestrictedEvenAsDefault verifies the same restriction
// applies when checker is reached implicitly as the default system (no
// X-System-Id header at all).
func TestKeylessSystemRestrictedEvenAsDefault(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "POST", "/mask", nil, map[string]string{"text": "x"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body %s", resp.StatusCode, data)
	}
}

// TestAPIKeyEnvUnsetFailsClosed verifies that a system configured with
// api_key_env but whose environment variable is unset (empty) is rejected
// with 401, never silently treated as keyless.
func TestAPIKeyEnvUnsetFailsClosed(t *testing.T) {
	os.Unsetenv("PDN_DEMO_KEY")
	_, ts := testServer(t, testConfig())
	resp, data := doJSON(t, ts, "POST", "/mask", map[string]string{
		"X-System-Id": "demo",
		"X-API-Key":   "anything",
	}, map[string]string{"text": "x"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body %s", resp.StatusCode, data)
	}
	// Even an empty key must not be accepted as "no key needed".
	resp2, data2 := doJSON(t, ts, "POST", "/mask", map[string]string{
		"X-System-Id": "demo",
	}, map[string]string{"text": "x"})
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body %s", resp2.StatusCode, data2)
	}
}

// --- A4: record ownership at the HTTP layer ---------------------------------

// TestMaskOwnershipConflict verifies /mask never overwrites a record owned by
// a different system: it fails (409/404 range) and the original owner's
// record is left intact.
func TestMaskOwnershipConflict(t *testing.T) {
	t.Setenv("PDN_DEMO_KEY", "demo-key")
	t.Setenv("PDN_CHATBOT_KEY", "chatbot-key")
	_, ts := testServer(t, testConfig())
	demo := map[string]string{"X-System-Id": "demo", "X-API-Key": "demo-key"}
	chatbot := map[string]string{"X-System-Id": "chatbot", "X-API-Key": "chatbot-key"}

	respA, dataA := doJSON(t, ts, "POST", "/mask", demo, map[string]string{"text": testText, "id": "shared-id"})
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("mask as demo: status = %d, body %s", respA.StatusCode, dataA)
	}
	var maskedA maskResponse
	if err := json.Unmarshal(dataA, &maskedA); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	respB, dataB := doJSON(t, ts, "POST", "/mask", chatbot, map[string]string{"text": "другой текст", "id": "shared-id"})
	if respB.StatusCode < 400 || respB.StatusCode >= 500 {
		t.Fatalf("mask as chatbot on demo's id: status = %d, want 4xx conflict/not-found, body %s", respB.StatusCode, dataB)
	}

	// demo's record must be unchanged.
	respA2, dataA2 := doJSON(t, ts, "POST", "/mask", demo, map[string]string{"text": testText, "id": "shared-id"})
	if respA2.StatusCode != http.StatusOK {
		t.Fatalf("mask as demo again: status = %d, body %s", respA2.StatusCode, dataA2)
	}
	var maskedA2 maskResponse
	if err := json.Unmarshal(dataA2, &maskedA2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if maskedA2.Masked != maskedA.Masked {
		t.Errorf("demo's record was disturbed: %q vs %q", maskedA2.Masked, maskedA.Masked)
	}
}

// TestUnmaskOwnershipNotFound verifies /unmask on a record owned by a
// different system behaves exactly like an unknown id: 404, not the restored
// content and not a store error. The rightful owner can still restore it
// (control case).
func TestUnmaskOwnershipNotFound(t *testing.T) {
	t.Setenv("PDN_DEMO_KEY", "demo-key")
	t.Setenv("PDN_DEMO2_KEY", "demo2-key")
	_, ts := testServer(t, testConfig())
	demo := map[string]string{"X-System-Id": "demo", "X-API-Key": "demo-key"}
	demo2 := map[string]string{"X-System-Id": "demo2", "X-API-Key": "demo2-key"}

	respA, dataA := doJSON(t, ts, "POST", "/mask", demo, map[string]string{"text": testText, "id": "owned-by-demo"})
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("mask as demo: status = %d, body %s", respA.StatusCode, dataA)
	}
	var maskedA maskResponse
	if err := json.Unmarshal(dataA, &maskedA); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// A foreign, but otherwise fully authorized and unmask-enabled, system
	// must not be able to restore demo's record.
	respForeign, dataForeign := doJSON(t, ts, "POST", "/unmask", demo2, map[string]string{"id": "owned-by-demo", "text": maskedA.Masked})
	if respForeign.StatusCode != http.StatusNotFound {
		t.Fatalf("unmask as foreign system: status = %d, want 404, body %s", respForeign.StatusCode, dataForeign)
	}
	if strings.Contains(string(dataForeign), "Иванов") || strings.Contains(string(dataForeign), "4509") {
		t.Errorf("foreign unmask leaked PII: %s", dataForeign)
	}

	// The rightful owner can still restore it.
	respOwner, dataOwner := doJSON(t, ts, "POST", "/unmask", demo, map[string]string{"id": "owned-by-demo", "text": maskedA.Masked})
	if respOwner.StatusCode != http.StatusOK {
		t.Fatalf("unmask as owner: status = %d, body %s", respOwner.StatusCode, dataOwner)
	}
	var restored unmaskResponse
	if err := json.Unmarshal(dataOwner, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Text != testText {
		t.Errorf("owner restore = %q, want %q", restored.Text, testText)
	}
}

// --- A8: request validation --------------------------------------------------

func TestProcessPayloadFieldRequired(t *testing.T) {
	_, ts := testServer(t, testConfig())
	// payload omitted entirely -> 400.
	resp, data := doJSON(t, ts, "POST", "/process", nil, map[string]string{"payload_id": "id1"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing payload: status = %d, want 400, body %s", resp.StatusCode, data)
	}

	// payload explicitly empty -> allowed.
	resp2, data2 := doJSON(t, ts, "POST", "/process", nil, map[string]string{"payload": "", "payload_id": "id2"})
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("explicit empty payload: status = %d, want 200, body %s", resp2.StatusCode, data2)
	}
}

// TestProcessTrailingDataRejected verifies a JSON body with extra data after
// the object is rejected with 400.
func TestProcessTrailingDataRejected(t *testing.T) {
	_, ts := testServer(t, testConfig())
	body := `{"payload":"x","payload_id":"id1"}{"smuggled":"object"}`
	req, err := http.NewRequest("POST", ts.URL+"/process", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(headerContentType, "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestChatUnknownRoleRejected verifies a message with a role outside
// system/user/assistant/tool is rejected with 400 before any upstream call.
func TestChatUnknownRoleRejected(t *testing.T) {
	called := false
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(500)
	}))
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", demoHeaders(t), map[string]interface{}{
		"messages": []map[string]string{{"role": "developer", "content": "x"}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body %s", resp.StatusCode, data)
	}
	if called {
		t.Errorf("upstream LLM was called for a request with an invalid role")
	}
}

// TestChatValidRolesAccepted verifies every allowed role passes validation.
func TestChatValidRolesAccepted(t *testing.T) {
	var captured []byte
	llm := fakeLLM(t, &captured)
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", demoHeaders(t), map[string]interface{}{
		"messages": []map[string]string{
			{"role": "system", "content": "be nice"},
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": "hello"},
			{"role": "tool", "content": "result"},
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body %s", resp.StatusCode, data)
	}
}

// --- A9: payload id length limit --------------------------------------------

func TestPayloadIDTooLong(t *testing.T) {
	_, ts := testServer(t, testConfig())
	longID := strings.Repeat("a", 300)

	resp, data := doJSON(t, ts, "POST", "/process", nil, map[string]string{"payload": "x", "payload_id": longID})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("/process: status = %d, want 400, body %s", resp.StatusCode, data)
	}

	resp2, data2 := doJSON(t, ts, "POST", "/mask", demoHeaders(t), map[string]string{"text": "x", "id": longID})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("/mask: status = %d, want 400, body %s", resp2.StatusCode, data2)
	}

	resp3, data3 := doJSON(t, ts, "POST", "/unmask", demoHeaders(t), map[string]string{"id": longID, "text": "x"})
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("/unmask: status = %d, want 400, body %s", resp3.StatusCode, data3)
	}
}

// --- D1: metrics on a separate listener -------------------------------------

// TestMetricsRemovedFromMainMuxWhenSeparate verifies that when
// server.metrics_addr is set, GET /metrics is no longer served on the main
// mux, while the standalone handler (what main.go wires to the separate
// listener) still works.
func TestMetricsRemovedFromMainMuxWhenSeparate(t *testing.T) {
	cfg := testConfig()
	cfg.Server.MetricsAddr = ":9090"
	s, ts := testServer(t, cfg)

	// Generate one request so the counters have at least one sample.
	doJSON(t, ts, "GET", "/healthz", nil, nil)

	resp, _ := doJSON(t, ts, "GET", "/metrics", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("main mux /metrics status = %d, want 404", resp.StatusCode)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	s.MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("standalone metrics handler status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pdn_requests_total") {
		t.Errorf("standalone metrics missing pdn_requests_total")
	}
}

// TestMetricsOnMainMuxByDefault verifies the old behaviour is preserved when
// metrics_addr is left empty.
func TestMetricsOnMainMuxByDefault(t *testing.T) {
	_, ts := testServer(t, testConfig())
	resp, _ := doJSON(t, ts, "GET", "/metrics", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// --- D3: chat timeouts and truncated streams --------------------------------

// TestChatUpstreamTimeoutReturns504 verifies that when the upstream LLM
// exceeds the configured timeout, the client gets a clean 504, not a hung
// connection or a generic 502.
func TestChatUpstreamTimeoutReturns504(t *testing.T) {
	block := make(chan struct{})
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer llm.Close()
	defer close(block)

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	cfg.LLM.Timeout = 100 * time.Millisecond
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", demoHeaders(t), map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
	})
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504, body %s", resp.StatusCode, data)
	}
}

// TestChatStreamWithoutDoneIsUpstreamError verifies that a stream which ends
// without a "[DONE]" marker (a dropped/truncated connection) is treated as an
// upstream error (502), not returned as if it were a complete answer.
func TestChatStreamWithoutDoneIsUpstreamError(t *testing.T) {
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		// Connection ends here without a [DONE] marker.
	}))
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", demoHeaders(t), map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body %s", resp.StatusCode, data)
	}
}

// --- D4: rejected requests and token accounting are observable -------------

// TestRejectedRequestsAreLoggedAndCounted verifies 401/403 responses go
// through the same request-log line and RequestsTotal counter as successful
// requests, so they are not invisible in metrics or logs.
func TestRejectedRequestsAreLoggedAndCounted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st, err := newMemoryStore(key)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(st.Close)
	cfg := testConfig()
	s := newServerWithLogger(cfg, st, logger)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// Unknown system -> 403.
	resp, _ := doJSON(t, ts, "POST", "/mask", map[string]string{"X-System-Id": "nope"}, map[string]string{"text": "x"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	logs := buf.String()
	if !strings.Contains(logs, `"status":403`) {
		t.Errorf("log missing the rejected request's status line:\n%s", logs)
	}

	metricsRec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(metricsRec, httptest.NewRequest("GET", "/metrics", nil))
	metricsBody := metricsRec.Body.String()
	if !strings.Contains(metricsBody, `status="403"`) {
		t.Errorf("pdn_requests_total missing a 403 sample:\n%s", metricsBody)
	}
}

// TestProcessMaskUnmaskRecordTokens verifies /process, /mask and /unmask all
// record an estimated token count in the request log (previously only chat
// did).
func TestProcessMaskUnmaskRecordTokens(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st, err := newMemoryStore(key)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(st.Close)
	cfg := testConfig()
	s := newServerWithLogger(cfg, st, logger)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	doJSON(t, ts, "POST", "/process", nil, map[string]string{"payload": testText, "payload_id": "tok1"})
	doJSON(t, ts, "POST", "/mask", demoHeaders(t), map[string]string{"text": testText, "id": "tok2"})
	doJSON(t, ts, "POST", "/unmask", demoHeaders(t), map[string]string{"id": "tok1", "text": testText})

	logs := buf.String()
	for _, route := range []string{`"route":"process"`, `"route":"mask"`, `"route":"unmask"`} {
		if !strings.Contains(logs, route) {
			t.Fatalf("log missing a line for %s:\n%s", route, logs)
		}
	}
	if !strings.Contains(logs, `"tokens"`) {
		t.Errorf("log missing token counts for process/mask/unmask:\n%s", logs)
	}
}
