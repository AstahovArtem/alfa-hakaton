package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"pdn-shield/internal/config"
	"pdn-shield/internal/metrics"
)

// LLMClient proxies requests to the upstream model gateway.
type LLMClient struct {
	baseURL string
	apiKey  string
	model   string
	timeout time.Duration
	client  *http.Client
	logger  *slog.Logger
	metrics *metrics.Metrics
}

// NewLLMClient builds an LLMClient.
func NewLLMClient(cfg config.LLM, logger *slog.Logger, m *metrics.Metrics) *LLMClient {
	return &LLMClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  envOr(cfg.APIKeyEnv, ""),
		model:   cfg.Model,
		timeout: cfg.Timeout,
		client:  &http.Client{Timeout: cfg.Timeout},
		logger:  logger,
		metrics: m,
	}
}

// chatMessage is one OpenAI chat message.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the OpenAI-compatible request body.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// usage is the token usage reported by the LLM.
type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// pdnInfo carries the masking metadata returned alongside the OpenAI response.
type pdnInfo struct {
	MaskedRequest string `json:"masked_request"`
	RawAnswer     string `json:"raw_answer"`
	MaskedCount   int    `json:"masked_count"`
	Unmasked      bool   `json:"unmasked"`
}

// chatResponse is the non-streaming OpenAI response returned to the client.
type chatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage usage    `json:"usage"`
	PDN   *pdnInfo `json:"pdn"`
}

// sseChunk is one streaming chunk from the upstream. Usage is only present on
// the final chunk of some gateways, when requested; when absent, token
// accounting falls back to the estimate in chat.go.
type sseChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *usage `json:"usage"`
}

// chatCompletion calls the upstream LLM with a masked request and returns the
// assembled assistant content and usage.
func (c *LLMClient) chatCompletion(ctx context.Context, req chatRequest) (string, chatResponse, error) {
	req.Model = c.model
	req.Stream = true // the AlfaGen gateway only accepts stream:true

	body, err := json.Marshal(req)
	if err != nil {
		return "", chatResponse{}, err
	}

	url := c.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", chatResponse{}, err
	}
	httpReq.Header.Set(headerContentType, "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	start := time.Now()
	resp, err := c.client.Do(httpReq)
	if err != nil {
		c.metrics.LLMDuration.Observe(time.Since(start).Seconds())
		return "", chatResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		c.metrics.LLMDuration.Observe(time.Since(start).Seconds())
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", chatResponse{}, fmt.Errorf("llm status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		c.metrics.LLMDuration.Observe(time.Since(start).Seconds())
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", chatResponse{}, fmt.Errorf("llm status %d", resp.StatusCode)
	}

	content, usage, err := readSSE(resp.Body)
	c.metrics.LLMDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		return "", chatResponse{}, err
	}

	out := chatResponse{
		ID:      "chatcmpl-" + randID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   c.model,
	}
	out.Choices = append(out.Choices, struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	}{Index: 0})
	out.Choices[0].Message.Role = "assistant"
	out.Choices[0].Message.Content = content
	out.Usage = usage
	return content, out, nil
}

// errStreamNotTerminated is returned by readSSE when the upstream connection
// ended without a "[DONE]" marker and without a finish_reason: the stream was
// cut short (dropped connection, upstream crash, proxy truncation), so any
// content collected so far cannot be trusted as complete.
var errStreamNotTerminated = errors.New("llm: stream ended without [DONE]")

// readSSE parses the SSE stream and concatenates delta.content fragments. It
// also picks up a usage block when a chunk carries one (some gateways attach
// it to the final chunk). A stream counts as complete when it sends "[DONE]"
// or a chunk with a finish_reason (some gateways omit "[DONE]"); otherwise it
// is reported as an error rather than silently returning partial content.
func readSSE(r io.Reader) (string, usage, error) {
	var content strings.Builder
	var usage usage
	sawDone := false
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			sawDone = true
			break
		}
		var chunk sseChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, ch := range chunk.Choices {
			content.WriteString(ch.Delta.Content)
			if ch.FinishReason != nil && *ch.FinishReason != "" {
				sawDone = true
			}
		}
		if chunk.Usage != nil {
			usage = *chunk.Usage
		}
	}
	if err := scanner.Err(); err != nil {
		return "", usage, err
	}
	if !sawDone {
		return "", usage, errStreamNotTerminated
	}
	return content.String(), usage, nil
}

// envOr returns the value of env name or def.
func envOr(name, def string) string {
	if name == "" {
		return def
	}
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func randID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%x", b)
}
