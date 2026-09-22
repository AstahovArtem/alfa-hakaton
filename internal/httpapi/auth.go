package httpapi

import (
	"crypto/subtle"
	"net/http"
	"os"

	"pdn-shield/internal/config"
)

// systemHeader is the header carrying the consumer system id.
const systemHeader = "X-System-Id"

// apiKeyHeader is the header carrying the system API key.
const apiKeyHeader = "X-API-Key"

// authResult is the outcome of identifying a system.
type authResult struct {
	system *config.System
	status int // 0 = ok, otherwise the HTTP status to return
}

// authenticate resolves the system from the request headers. For POST /process
// without headers the default system is used. It returns a status of 0 on
// success.
func (s *Server) authenticate(r *http.Request, allowDefault bool) authResult {
	sysID := r.Header.Get(systemHeader)
	key := r.Header.Get(apiKeyHeader)

	if sysID == "" && allowDefault && s.cfg.Server.DefaultSystem != "" {
		sysID = s.cfg.Server.DefaultSystem
	}

	if sysID == "" {
		return authResult{status: http.StatusForbidden}
	}

	sys := s.cfg.SystemByID(sysID)
	if sys == nil || !sys.Enabled {
		return authResult{status: http.StatusForbidden}
	}

	// If the system has a key configured, it must match. Keys come from env
	// (api_key_env) or, for the checker, from the literal api_key field.
	expected := ""
	if sys.APIKeyEnv != "" {
		expected = os.Getenv(sys.APIKeyEnv)
	} else {
		expected = sys.APIKey
	}
	if expected != "" && !constantTimeEqual(expected, key) {
		return authResult{status: http.StatusUnauthorized}
	}

	return authResult{system: sys}
}

// constantTimeEqual compares two strings in constant time.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
