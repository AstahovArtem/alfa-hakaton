package httpapi

import (
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

	strategy, status := s.strategyOverride(sys, req.Strategy)
	if status != 0 {
		if status == http.StatusForbidden {
			writeError(w, status, "strategy override not allowed")
		} else {
			writeError(w, status, "unknown strategy")
		}
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
	reqTokens := 0
	for _, m := range maskedMessages {
		reqTokens += metrics.EstimateTokens(m.Content)
	}
	s.metrics.Tokens.WithLabelValues("mask").Add(float64(reqTokens))

	start := time.Now()
	content, resp, err := s.llm.chatCompletion(r.Context(), chatRequest{
		Model:    req.Model,
		Messages: maskedMessages,
		Stream:   req.Stream,
	})
	if err != nil {
		s.logger.Error("llm unavailable", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":  "llm unavailable",
			"detail": "upstream model gateway error",
		})
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

	// Token accounting from the LLM usage when available.
	if resp.Usage.TotalTokens > 0 {
		s.metrics.Tokens.WithLabelValues("proxy").Add(float64(resp.Usage.TotalTokens))
	}

	w.Header().Set("X-PDN-Masked-Count", strconv.Itoa(countFound(totalFound)))
	w.Header().Set("X-PDN-Latency-Ms", strconv.Itoa(int(latency)))
	writeJSON(w, http.StatusOK, resp)
}

// maskMessages masks all message contents under one id with a shared DocState
// so equal values across messages get the same replacement. It returns the id,
// the masked messages, the total found counts, the stage timings, the total
// input length and whether the handler should continue.
func (s *Server) maskMessages(w http.ResponseWriter, r *http.Request, req chatRequestIn, opt engine.Options) (string, []chatMessage, map[string]int, engine.Stages, int, bool) {
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
		writeError(w, http.StatusInternalServerError, "masking failed")
		return "", nil, nil, engine.Stages{}, 0, false
	}
	s.recordFound(mbres.Found)
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
func (s *Server) unmaskAnswer(w http.ResponseWriter, r *http.Request, sys *configSystem, id, content string, info *reqInfo) (string, bool) {
	if !sys.Unmask {
		return content, true
	}
	ures, err := s.engine.UnmaskEx(r.Context(), id, content)
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
