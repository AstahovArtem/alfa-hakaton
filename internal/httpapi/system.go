package httpapi

import (
	"context"
	"net/http"

	"pdn-shield/internal/config"
	"pdn-shield/internal/engine"
)

// configSystem is an alias to keep handler signatures readable.
type configSystem = config.System

// ctxSystemKey is the private context key for the system that wrap() already
// authenticated for this request.
type ctxSystemKey struct{}

// withSystem attaches the authenticated system to ctx.
func withSystem(ctx context.Context, sys *configSystem) context.Context {
	return context.WithValue(ctx, ctxSystemKey{}, sys)
}

// systemFromCtx returns the system attached by wrap(), or nil when none was
// attached (a public route, or a request that never went through wrap()).
func systemFromCtx(ctx context.Context) *configSystem {
	sys, _ := ctx.Value(ctxSystemKey{}).(*configSystem)
	return sys
}

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
		return &config.System{Strategy: strategyPartial, Unmask: true}
	}
	return sys
}

// optionsFor builds engine options from a system config, including the
// ownership fields (SystemID/DefaultSystemID) the engine uses to reject
// access to a record owned by a different system.
func (s *Server) optionsFor(sys *configSystem) engine.Options {
	opt := engine.Options{
		Categories:      sys.Categories,
		Strategy:        sys.Strategy,
		TTL:             s.cfg.Store.TTL,
		Unmask:          sys.Unmask,
		SystemID:        sys.ID,
		DefaultSystemID: s.cfg.Server.DefaultSystem,
	}
	if opt.Strategy == "" {
		opt.Strategy = strategyPartial
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
