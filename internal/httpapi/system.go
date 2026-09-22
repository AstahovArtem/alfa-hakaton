package httpapi

import (
	"net/http"

	"pdn-shield/internal/config"
	"pdn-shield/internal/engine"
)

// configSystem is an alias to keep handler signatures readable.
type configSystem = config.System

// resolveSystem re-resolves the authenticated system from the request. It is
// called after wrap() has already validated the system, so it always succeeds.
func (s *Server) resolveSystem(r *http.Request) *configSystem {
	sysID := r.Header.Get(systemHeader)
	if sysID == "" {
		sysID = s.cfg.Server.DefaultSystem
	}
	sys := s.cfg.SystemByID(sysID)
	if sys == nil {
		// Fall back to the first enabled system; this should not happen.
		for i := range s.cfg.Systems {
			if s.cfg.Systems[i].Enabled {
				return &s.cfg.Systems[i]
			}
		}
		return &config.System{Strategy: "partial", Unmask: true}
	}
	return sys
}

// optionsFor builds engine options from a system config.
func (s *Server) optionsFor(sys *configSystem) engine.Options {
	opt := engine.Options{
		Categories: sys.Categories,
		Strategy:   sys.Strategy,
		TTL:        s.cfg.Store.TTL,
	}
	if opt.Strategy == "" {
		opt.Strategy = "partial"
	}
	for _, r := range sys.ComboRules {
		opt.ComboRules = append(opt.ComboRules, engine.ComboRule{
			Category:    r.Category,
			RequiresAny: r.RequiresAny,
		})
	}
	return opt
}

// strategyOverride resolves a per-request strategy override against a system.
// override is the raw value of the optional "strategy" field. When it is empty
// the system's configured strategy is returned. When the system is not allowed
// to override, a 403 status is returned; when the strategy is unknown, a 400
// status is returned. A status of 0 means success.
func (s *Server) strategyOverride(sys *configSystem, override string) (string, int) {
	if override == "" {
		return sys.Strategy, 0
	}
	if !sys.AllowStrategyOverride {
		return "", http.StatusForbidden
	}
	if !config.ValidStrategy(override) {
		return "", http.StatusBadRequest
	}
	return override, 0
}
