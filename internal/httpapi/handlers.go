package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"pdn-shield/internal/engine"
	"pdn-shield/internal/pii"
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

// handleProcess implements the checker contract: mask, or unmask when the
// payload looks like a stored mask.
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	var req processRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.PayloadID == "" {
		writeError(w, http.StatusBadRequest, "payload_id is required")
		return
	}

	info := reqInfoFrom(r.Context())
	if info != nil {
		info.payloadID = req.PayloadID
		info.textLen = len(req.Payload)
	}

	sys := s.systemFrom(r)
	opt := s.optionsFor(sys)

	res, err := s.engine.Process(r.Context(), req.PayloadID, req.Payload, opt)
	if err != nil {
		s.handleProcessError(w, err)
		return
	}

	if info != nil {
		recordProcessInfo(info, res)
	}

	if res.Unmasked && res.Misses > 0 {
		s.logger.Warn("process unmask with misses", "payload_id", req.PayloadID, "misses", res.Misses)
	}
	if res.Found != nil {
		s.recordFound(res.Found)
	}
	writeJSON(w, http.StatusOK, processResponse{Result: res.Result})
}

// handleProcessError writes the appropriate error response for a Process failure.
func (s *Server) handleProcessError(w http.ResponseWriter, err error) {
	if isStoreError(err) {
		s.storeUnavailable(w, opLoad, err)
		return
	}
	writeError(w, http.StatusInternalServerError, "processing failed")
}

// recordProcessInfo fills the request info with the process result details.
func recordProcessInfo(info *reqInfo, res engine.ProcessResult) {
	info.stages = res.Stages
	if res.Unmasked {
		info.direction = dirUnmask
		info.misses = res.Misses
		return
	}
	info.direction = dirMask
	info.found = res.Found
}

// maskRequest is the /mask body.
type maskRequest struct {
	Text     string `json:"text"`
	ID       string `json:"id"`
	Strategy string `json:"strategy"`
}

// maskResponse is the /mask response.
type maskResponse struct {
	ID        string         `json:"id"`
	Masked    string         `json:"masked"`
	Found     map[string]int `json:"found"`
	Strategy  string         `json:"strategy"`
	LatencyMs int64          `json:"latency_ms"`
}

// handleMask masks a text and returns the id and masked result.
func (s *Server) handleMask(w http.ResponseWriter, r *http.Request) {
	var req maskRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.Text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	id, ok := resolveMaskID(w, req.ID)
	if !ok {
		return
	}

	sys := s.systemFrom(r)
	strategy, status := s.strategyOverride(sys, req.Strategy)
	if status != 0 {
		writeStrategyError(w, status)
		return
	}
	opt := s.optionsFor(sys)
	opt.Strategy = strategy
	start := time.Now()
	mres, err := s.engine.MaskEx(r.Context(), id, req.Text, opt)
	if err != nil {
		s.handleMaskError(w, err)
		return
	}
	masked := mres.Masked
	found := mres.Found
	s.recordFound(found)
	latency := time.Since(start).Milliseconds()

	if info := reqInfoFrom(r.Context()); info != nil {
		info.payloadID = id
		info.direction = dirMask
		info.textLen = len(req.Text)
		info.found = found
		info.stages = mres.Stages
	}

	writeJSON(w, http.StatusOK, maskResponse{
		ID:        id,
		Masked:    masked,
		Found:     categoryMap(found),
		Strategy:  strategy,
		LatencyMs: latency,
	})
}

// resolveMaskID returns the request id, generating a new one when absent.
func resolveMaskID(w http.ResponseWriter, id string) (string, bool) {
	if id != "" {
		return id, true
	}
	generated, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return "", false
	}
	return generated, true
}

// writeStrategyError writes the error response for a failed strategy override.
func writeStrategyError(w http.ResponseWriter, status int) {
	if status == http.StatusForbidden {
		writeError(w, status, "strategy override not allowed")
		return
	}
	writeError(w, status, "unknown strategy")
}

// handleMaskError writes the appropriate error response for a MaskEx failure.
func (s *Server) handleMaskError(w http.ResponseWriter, err error) {
	if isStoreError(err) {
		s.storeUnavailable(w, "save", err)
		return
	}
	writeError(w, http.StatusInternalServerError, "masking failed")
}

// unmaskRequest is the /unmask body.
type unmaskRequest struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// unmaskResponse is the /unmask response.
type unmaskResponse struct {
	Text   string `json:"text"`
	Misses int    `json:"misses"`
}

// handleUnmask restores the original text for an id.
func (s *Server) handleUnmask(w http.ResponseWriter, r *http.Request) {
	sys := s.systemFrom(r)
	if !sys.Unmask {
		writeError(w, http.StatusForbidden, "unmask not allowed for this system")
		return
	}
	var req unmaskRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.ID == "" || req.Text == "" {
		writeError(w, http.StatusBadRequest, "id and text are required")
		return
	}
	ures, err := s.engine.UnmaskEx(r.Context(), req.ID, req.Text)
	if err != nil {
		if isStoreError(err) {
			s.storeUnavailable(w, opLoad, err)
			return
		}
		writeError(w, http.StatusNotFound, "record not found")
		return
	}
	if info := reqInfoFrom(r.Context()); info != nil {
		info.payloadID = req.ID
		info.direction = dirUnmask
		info.textLen = len(req.Text)
		info.misses = ures.Misses
		info.stages = ures.Stages
	}
	writeJSON(w, http.StatusOK, unmaskResponse{Text: ures.Restored, Misses: ures.Misses})
}

// systemFrom returns the authenticated system from the request context.
func (s *Server) systemFrom(r *http.Request) *configSystem {
	// The system is resolved in wrap(); here we re-resolve cheaply.
	return s.resolveSystem(r)
}

// recordFound increments the PII found metrics.
func (s *Server) recordFound(found map[pii.Category]int) {
	for cat, n := range found {
		s.metrics.PIIFound.WithLabelValues(string(cat)).Add(float64(n))
	}
}

// categoryMap converts a category->count map to string keys for JSON.
func categoryMap(found map[pii.Category]int) map[string]int {
	out := make(map[string]int, len(found))
	for c, n := range found {
		out[string(c)] = n
	}
	return out
}

// newUUID generates a random UUID v4.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst), nil
}
