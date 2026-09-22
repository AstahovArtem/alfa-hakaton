package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"pdn-shield/internal/metrics"
)

// chatRequestIn is the incoming OpenAI-compatible request.
type chatRequestIn struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// handleChat proxies a chat completion request: masks all messages under one
// id, calls the LLM, unmasks the response and returns a non-streaming answer.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	sys := s.systemFrom(r)
	opt := s.optionsFor(sys)

	var req chatRequestIn
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages are required")
		return
	}

	// Mask all message contents under one id with a shared DocState so equal
	// values across messages get the same replacement.
	id, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	texts := make([]string, len(req.Messages))
	for i, m := range req.Messages {
		texts[i] = m.Content
	}
	mbres, err := s.engine.MaskBatchEx(r.Context(), id, texts, opt)
	if err != nil {
		if isStoreError(err) {
			s.storeUnavailable(w, "save", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "masking failed")
		return
	}
	maskedTexts := mbres.Masked
	found := mbres.Found
	s.recordFound(found)
	totalFound := categoryMap(found)
	maskedMessages := make([]chatMessage, len(req.Messages))
	for i, m := range req.Messages {
		maskedMessages[i] = chatMessage{Role: m.Role, Content: maskedTexts[i]}
	}

	info := reqInfoFrom(r.Context())
	if info != nil {
		info.payloadID = id
		info.direction = "proxy"
		info.found = found
		info.stages = mbres.Stages
		for _, t := range texts {
			info.textLen += len(t)
		}
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
	answer := content
	if sys.Unmask {
		ures, err := s.engine.UnmaskEx(r.Context(), id, content)
		if err == nil {
			answer = ures.Restored
			if info != nil {
				info.misses = ures.Misses
				info.stages.StoreMs += ures.Stages.StoreMs
			}
			if ures.Misses > 0 {
				s.logger.Warn("chat unmask with misses", "payload_id", id, "misses", ures.Misses)
			}
		} else if isStoreError(err) {
			s.storeUnavailable(w, "load", err)
			return
		}
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

// countFound sums the values of a category count map.
func countFound(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
