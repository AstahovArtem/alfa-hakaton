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
// #nosec G101 -- header name constant, not a credential value.
const apiKeyHeader = "X-API-Key"

// authResult is the outcome of identifying a system.
type authResult struct {
	system *config.System
	status int // 0 = ok, otherwise the HTTP status to return
}

// authenticate resolves the system from the request headers for route. For
// POST /process without headers the default system is used. A system whose
// expected key is empty (a "keyless" system, e.g. the hackathon checker) is
// usable ONLY on POST /process: on every other route it is rejected with 403,
// even when its id is sent explicitly via X-System-Id. A system configured
// with api_key_env but an empty (unset) environment variable fails closed
// with 401, rather than being silently treated as keyless. It returns a
// status of 0 on success.
func (s *Server) authenticate(r *http.Request, route string) authResult {
	sysID := r.Header.Get(systemHeader)
	key := r.Header.Get(apiKeyHeader)

	allowDefault := route == routeProcess
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

	expected, determined := expectedKey(sys)
	if !determined {
		// api_key_env is set but the environment variable is empty: fail
		// closed rather than treating the system as keyless.
		return authResult{status: http.StatusUnauthorized}
	}
	if expected == "" {
		// A genuinely keyless system may only be used on POST /process.
		if route != routeProcess {
			return authResult{status: http.StatusForbidden}
		}
		return authResult{system: sys}
	}
	if !constantTimeEqual(expected, key) {
		return authResult{status: http.StatusUnauthorized}
	}

	return authResult{system: sys}
}

// expectedKey returns the expected API key for sys and whether it could be
// determined. Keys come from env (api_key_env) or, for a literal-key system
// like the checker, from the literal api_key field. When api_key_env is set
// but the environment variable is empty, determined is false so the caller
// fails closed instead of treating the system as keyless.
func expectedKey(sys *config.System) (key string, determined bool) {
	if sys.APIKeyEnv != "" {
		v := os.Getenv(sys.APIKeyEnv)
		if v == "" {
			return "", false
		}
		return v, true
	}
	return sys.APIKey, true
}

// constantTimeEqual compares two strings in constant time.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
