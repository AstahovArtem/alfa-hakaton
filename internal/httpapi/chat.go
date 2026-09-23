package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"pdn-shield/internal/engine"
	"pdn-shield/internal/metrics"
)

// chatRequestIn is the incoming OpenAI-compatible request.
type chatRequestIn struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	// Strategy is an optional masking-strategy override, outside the OpenAI
	// schema. It is removed before the request is forwarded to the LLM.
	Strategy string `json:"strategy"`
}

// allowedRoles are the OpenAI chat message roles this proxy accepts. Anything
// else is rejected before any masking or upstream call.
var allowedRoles = map[string]bool{
	"system":    true,
	"user":      true,
	"assistant": true,
	"tool":      true,
}

// messagesHaveValidRoles reports whether every message's role is in
// allowedRoles. It runs before masking or the upstream call, so a malformed
// request never reaches the LLM.
func messagesHaveValidRoles(messages []chatMessage) bool {
	for _, m := range messages {
		if !allowedRoles[m.Role] {
			return false
		}
	}
	return true
}

// handleChat proxies a chat completion request: masks all messages under one
// id, calls the LLM, unmasks the response and returns a non-streaming answer.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	sys := s.systemFrom(r)

	var req chatRequestIn
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages are required")
		return
	}
	if !messagesHaveValidRoles(req.Messages) {
		writeError(w, http.StatusBadRequest, "unknown message role")
		return
	}

	strategy, status := s.strategyOverride(sys, req.Strategy)
	if status != 0 {
		writeStrategyError(w, status)
		return
	}
	opt := s.optionsFor(sys)
	opt.Strategy = strategy

	// Mask all message contents under one id with a shared DocState so equal
	// values across messages get the same replacement.
	id, maskedMessages, totalFound, stages, textLen, ok := s.maskMessages(w, r, req, opt)
	if !ok {
		return
	}

	info := reqInfoFrom(r.Context())
	if info != nil {
		info.payloadID = id
		info.direction = "proxy"
		info.stages = stages
		info.textLen = textLen
	}

	// Estimate tokens for the masked request.
	reqTokens := estimateTokens(maskedMessages)
	s.metrics.Tokens.WithLabelValues(dirMask).Add(float64(reqTokens))

	start := time.Now()
	content, resp, err := s.llm.chatCompletion(r.Context(), chatRequest{
		Model:    req.Model,
		Messages: maskedMessages,
		Stream:   req.Stream,
	})
	if err != nil {
		s.handleLLMError(w, err)
		return
	}
	latency := time.Since(start).Milliseconds()
	if info != nil {
		info.stages.LLMMs = latency
	}

	// Unmask the assistant response if the system allows it.
	answer, ok := s.unmaskAnswer(w, r, sys, id, content, info)
	if !ok {
		return
	}
	resp.Choices[0].Message.Content = answer

	// Attach masking metadata so the demo can show the three stages: what was
	// sent to the LLM, the raw answer and the unmasked answer.
	resp.PDN = &pdnInfo{
		MaskedRequest: lastUserContent(maskedMessages),
		RawAnswer:     content,
		MaskedCount:   countFound(totalFound),
		Unmasked:      sys.Unmask,
	}

	// Token accounting from the LLM usage when available.
	if resp.Usage.TotalTokens > 0 {
		s.metrics.Tokens.WithLabelValues("proxy").Add(float64(resp.Usage.TotalTokens))
	}

	w.Header().Set("X-PDN-Masked-Count", strconv.Itoa(countFound(totalFound)))
	w.Header().Set("X-PDN-Latency-Ms", strconv.Itoa(int(latency)))
	writeJSON(w, http.StatusOK, resp)
}

// estimateTokens sums the estimated token count of the masked messages.
func estimateTokens(messages []chatMessage) int {
	n := 0
	for _, m := range messages {
		n += metrics.EstimateTokens(m.Content)
	}
	return n
}

// handleLLMError writes the error response when the LLM call fails. An
// upstream timeout is reported as 504 (the client made a valid request but
// the gateway did not answer in time); every other failure (unreachable,
// 5xx, malformed/truncated stream) is a 502.
func (s *Server) handleLLMError(w http.ResponseWriter, err error) {
	s.logger.Error("llm unavailable", "err", err)
	if isUpstreamTimeout(err) {
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{
			"error":  "llm timeout",
			"detail": "upstream model gateway did not respond in time",
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{
		"error":  "llm unavailable",
		"detail": "upstream model gateway error",
	})
}

// isUpstreamTimeout reports whether err stems from the LLM client's request
// timeout expiring (net/http wraps this as a context.DeadlineExceeded).
func isUpstreamTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// maskMessages masks all message contents under one id with a shared DocState
// so equal values across messages get the same replacement. It returns the id,
// the masked messages, the total found counts, the stage timings, the total
// input length and whether the handler should continue.
func (s *Server) maskMessages(
	w http.ResponseWriter,
	r *http.Request,
	req chatRequestIn,
	opt engine.Options,
) (string, []chatMessage, map[string]int, engine.Stages, int, bool) {
	id, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return "", nil, nil, engine.Stages{}, 0, false
	}
	texts := make([]string, len(req.Messages))
	for i, m := range req.Messages {
		texts[i] = m.Content
	}
	mbres, err := s.engine.MaskBatchEx(r.Context(), id, texts, opt)
	if err != nil {
		if isStoreError(err) {
			s.storeUnavailable(w, "save", err)
			return "", nil, nil, engine.Stages{}, 0, false
		}
		if errors.Is(err, engine.ErrForeignRecord) {
			// A freshly generated UUID collided with an existing record's id
			// (astronomically unlikely); refuse rather than overwrite it.
			writeError(w, http.StatusConflict, "id already in use")
			return "", nil, nil, engine.Stages{}, 0, false
		}
		writeError(w, http.StatusInternalServerError, "masking failed")
		return "", nil, nil, engine.Stages{}, 0, false
	}
	s.recordFound(mbres.Found)
	if info := reqInfoFrom(r.Context()); info != nil {
		info.found = mbres.Found
	}
	// The optional OpenAI "name" field on a message can carry PII (a display
	// name); it is dropped rather than forwarded, since chatMessage has no
	// Name field to copy it into.
	maskedMessages := make([]chatMessage, len(req.Messages))
	for i, m := range req.Messages {
		maskedMessages[i] = chatMessage{Role: m.Role, Content: mbres.Masked[i]}
	}
	textLen := 0
	for _, t := range texts {
		textLen += len(t)
	}
	return id, maskedMessages, categoryMap(mbres.Found), mbres.Stages, textLen, true
}

// unmaskAnswer restores the assistant response when the system allows it. It
// returns the answer to send to the client and whether the handler should
// continue. When the store is unavailable it writes a 503 and returns false.
func (s *Server) unmaskAnswer(
	w http.ResponseWriter,
	r *http.Request,
	sys *configSystem,
	id, content string,
	info *reqInfo,
) (string, bool) {
	if !sys.Unmask {
		return content, true
	}
	ures, err := s.engine.UnmaskEx(r.Context(), id, content, s.optionsFor(sys))
	if err != nil {
		if isStoreError(err) {
			s.storeUnavailable(w, "load", err)
			return "", false
		}
		return content, true
	}
	if info != nil {
		info.misses = ures.Misses
		info.stages.StoreMs += ures.Stages.StoreMs
	}
	if ures.Misses > 0 {
		s.logger.Warn("chat unmask with misses", "payload_id", id, "misses", ures.Misses)
	}
	return ures.Restored, true
}

// countFound sums the values of a category count map.
func countFound(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// lastUserContent returns the content of the last user message, or "" when
// there is none.
func lastUserContent(messages []chatMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}
