package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeLLM returns an httptest server that records the request body and replies
// with SSE chunks echoing the masked content.
func fakeLLM(t *testing.T, captured *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*captured = body

		var req chatRequest
		_ = json.Unmarshal(body, &req)
		content := ""
		if len(req.Messages) > 0 {
			content = req.Messages[0].Content
		}

		w.Header().Set(headerContentType, "text/event-stream")
		// Echo the masked content back in one chunk.
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", content)
		fmt.Fprintf(w, "data: [DONE]\n\n")
	}))
}

func TestChatProxyMasksAndUnmasks(t *testing.T) {
	var captured []byte
	llm := fakeLLM(t, &captured)
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", checkerHeaders(), map[string]interface{}{
		"model":    "test-model",
		"messages": []map[string]string{{"role": "user", "content": testText}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body %s", resp.StatusCode, data)
	}

	// The request sent to the fake LLM must not contain the original PII.
	if bytes.Contains(captured, []byte("Иванов")) || bytes.Contains(captured, []byte("4509")) {
		t.Errorf("LLM request leaked PII: %s", captured)
	}

	// The client must receive the unmasked response.
	var cresp chatResponse
	if err := json.Unmarshal(data, &cresp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cresp.Choices) == 0 {
		t.Fatalf("no choices in response")
	}
	got := cresp.Choices[0].Message.Content
	if got != testText {
		t.Errorf("unmasked response = %q, want %q", got, testText)
	}

	// Headers.
	if resp.Header.Get("X-PDN-Masked-Count") == "" {
		t.Errorf("missing X-PDN-Masked-Count header")
	}
	if resp.Header.Get("X-PDN-Latency-Ms") == "" {
		t.Errorf("missing X-PDN-Latency-Ms header")
	}
}

func TestChatProxyLLMUnavailable(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.BaseURL = "http://127.0.0.1:1" // unreachable
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", checkerHeaders(), map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
	})
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d, want 502, body %s", resp.StatusCode, data)
	}
	if !strings.Contains(string(data), "llm unavailable") {
		t.Errorf("body = %s", data)
	}
}

func TestChatProxyLLM5xx(t *testing.T) {
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", checkerHeaders(), map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": testText}},
	})
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d, want 502, body %s", resp.StatusCode, data)
	}
}

// TestChatProxySharedDocState verifies that the same PII value in different
// messages gets the same replacement (shared DocState).
func TestChatProxySharedDocState(t *testing.T) {
	var captured []byte
	llm := fakeLLM(t, &captured)
	defer llm.Close()

	cfg := testConfig()
	cfg.LLM.BaseURL = llm.URL
	_, ts := testServer(t, cfg)

	resp, data := doJSON(t, ts, "POST", "/v1/chat/completions", checkerHeaders(), map[string]interface{}{
		"messages": []map[string]string{
			{"role": "user", "content": "Мой телефон +7 (916) 123-45-67"},
			{"role": "user", "content": "Позвоните на +7 (916) 123-45-67"},
		},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body %s", resp.StatusCode, data)
	}

	// The masked request must contain the same replacement for the phone in
	// both messages.
	var req chatRequest
	if err := json.Unmarshal(captured, &req); err != nil {
		t.Fatalf("unmarshal captured: %v", err)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("messages = %d", len(req.Messages))
	}
	m1 := req.Messages[0].Content
	m2 := req.Messages[1].Content
	// Extract the masked phone token from each message.
	p1 := maskedPhone(m1)
	p2 := maskedPhone(m2)
	if p1 == "" || p2 == "" {
		t.Fatalf("could not find masked phone: %q / %q", m1, m2)
	}
	if p1 != p2 {
		t.Errorf("same value got different replacements: %q vs %q", p1, p2)
	}
}

// maskedPhone extracts the masked phone fragment from a message.
func maskedPhone(s string) string {
	// The partial strategy keeps the first 2 and last 2 digits: "+7 (9**) ***-**-67".
	idx := strings.Index(s, "+7")
	if idx < 0 {
		return ""
	}
	return s[idx:]
}

// TestNoPIIInLogs runs a request with PII through the handler with a logger
// writing to a buffer and asserts no PII value appears in the buffer.
func TestNoPIIInLogs(t *testing.T) {
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

	// Run a mask and an unmask with PII.
	resp, data := doJSON(t, ts, "POST", "/mask", checkerHeaders(), map[string]string{"text": testText})
	if resp.StatusCode != 200 {
		t.Fatalf("mask status = %d", resp.StatusCode)
	}
	var mres maskResponse
	_ = json.Unmarshal(data, &mres)

	doJSON(t, ts, "POST", "/unmask", checkerHeaders(), map[string]string{"id": mres.ID, "text": mres.Masked})

	logs := buf.String()
	assertNoPIILeak(t, logs)
	assertLogContains(t, logs, `"payload_id":"`+mres.ID+`"`, "log missing payload_id %q:\n%s", mres.ID)
	assertLogContains(t, logs, `"direction":"mask"`, "log missing mask direction:\n%s")
	assertLogContains(t, logs, `"direction":"unmask"`, "log missing unmask direction:\n%s")
	for _, cat := range []string{"full_name", "passport", "phone"} {
		assertLogContains(t, logs, `"`+cat+`":1`, "log missing found category %q:\n%s", cat)
	}
}

// assertNoPIILeak fails when any known PII value appears in the log buffer.
func assertNoPIILeak(t *testing.T, logs string) {
	t.Helper()
	for _, piiVal := range []string{"Иванов", "4509", "123-45-67"} {
		if strings.Contains(logs, piiVal) {
			t.Errorf("log leaked PII value %q:\n%s", piiVal, logs)
		}
	}
}

// assertLogContains fails when the log buffer does not contain the substring.
func assertLogContains(t *testing.T, logs, substr, format string, args ...any) {
	t.Helper()
	if !strings.Contains(logs, substr) {
		t.Errorf(format+"\n%s", append(args, logs)...)
	}
}
