// Package config loads and validates the pdn-shield configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"pdn-shield/internal/pii"
)

// Masking strategy names.
const (
	StrategyPartial   = "partial"
	StrategyFull      = "full"
	StrategyToken     = "token"
	StrategySynthetic = "synthetic"
)

// Server configures the HTTP server.
type Server struct {
	Addr          string        `yaml:"addr"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	MaxBodyBytes  int64         `yaml:"max_body_bytes"`
	MaxInflight   int           `yaml:"max_inflight"`
	DefaultSystem string        `yaml:"default_system"`
}

// Store configures the persistence backend.
type Store struct {
	Kind             string        `yaml:"kind"`
	RedisAddr        string        `yaml:"redis_addr"`
	RedisPool        int           `yaml:"redis_pool"`
	RedisWait        time.Duration `yaml:"redis_wait"`
	RedisTimeout     time.Duration `yaml:"redis_timeout"`
	TTL              time.Duration `yaml:"ttl"`
	EncryptionKeyEnv string        `yaml:"encryption_key_env"`
}

// LLM configures the upstream model gateway.
type LLM struct {
	BaseURL    string        `yaml:"base_url"`
	APIKeyEnv  string        `yaml:"api_key_env"`
	Model      string        `yaml:"model"`
	Timeout    time.Duration `yaml:"timeout"`
	StreamOnly bool          `yaml:"stream_only"`
}

// Logging configures slog output.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// System is one consumer system allowed to call the service.
type System struct {
	ID         string         `yaml:"id"`
	Enabled    bool           `yaml:"enabled"`
	APIKey     string         `yaml:"api_key"` // literal key; empty = not required
	APIKeyEnv  string         `yaml:"api_key_env"`
	Categories []pii.Category `yaml:"categories"`
	Strategy   string         `yaml:"strategy"`
	Unmask     bool           `yaml:"unmask"`
	// AllowStrategyOverride permits a per-request "strategy" field on /mask and
	// the chat proxy to override the system's configured strategy.
	AllowStrategyOverride bool        `yaml:"allow_strategy_override"`
	ComboRules            []ComboRule `yaml:"combo_rules"`
}

// ComboRule is the config form of an engine combo rule.
type ComboRule struct {
	Category    pii.Category   `yaml:"category"`
	RequiresAny []pii.Category `yaml:"requires_any"`
}

// Config is the root configuration.
type Config struct {
	Server  Server   `yaml:"server"`
	Store   Store    `yaml:"store"`
	LLM     LLM      `yaml:"llm"`
	Logging Logging  `yaml:"logging"`
	Systems []System `yaml:"systems"`
}

// validStrategies are the strategies the engine knows.
var validStrategies = map[string]bool{
	StrategyPartial:   true,
	StrategyFull:      true,
	StrategyToken:     true,
	StrategySynthetic: true,
}

// ValidStrategy reports whether name is a known masking strategy.
func ValidStrategy(name string) bool {
	return validStrategies[name]
}

// validCategories are all categories the pipeline can produce.
var validCategories = map[pii.Category]bool{
	pii.CatFullName: true, pii.CatBirthDate: true, pii.CatBirthPlace: true,
	pii.CatPassport: true, pii.CatCitizenship: true, pii.CatPassportIssuer: true,
	pii.CatDivisionCode: true, pii.CatPassportDate: true, pii.CatDriverLicense: true,
	pii.CatAddress: true, pii.CatEmail: true, pii.CatPhone: true, pii.CatINN: true,
	pii.CatCardNumber: true, pii.CatCVV: true, pii.CatPIN: true, pii.CatCardHolder: true,
	pii.CatSNILS: true, pii.CatForeignPassport: true, pii.CatDate: true,
}

// Load reads and validates the config from path.
func Load(path string) (*Config, error) {
	// #nosec G304 -- path is operator-controlled (CLI flag/env), not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the config for unknown strategies, categories and missing
// required fields.
func (c *Config) Validate() error {
	if err := c.validateBasics(); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, s := range c.Systems {
		if s.ID == "" {
			return fmt.Errorf("config: system id is required")
		}
		if seen[s.ID] {
			return fmt.Errorf("config: duplicate system id %q", s.ID)
		}
		seen[s.ID] = true
		if err := validateSystem(s); err != nil {
			return err
		}
	}
	return nil
}

// validateBasics checks the server, store and LLM sections.
func (c *Config) validateBasics() error {
	if c.Server.Addr == "" {
		return fmt.Errorf("config: server.addr is required")
	}
	if c.Server.MaxInflight <= 0 {
		return fmt.Errorf("config: server.max_inflight must be positive")
	}
	if c.Store.Kind != "memory" && c.Store.Kind != "redis" {
		return fmt.Errorf("config: store.kind must be memory or redis, got %q", c.Store.Kind)
	}
	if c.Store.Kind == "redis" && c.Store.RedisAddr == "" {
		return fmt.Errorf("config: store.redis_addr is required for redis store")
	}
	if c.LLM.BaseURL == "" {
		return fmt.Errorf("config: llm.base_url is required")
	}
	if c.LLM.Model == "" {
		return fmt.Errorf("config: llm.model is required")
	}
	return nil
}

// validateSystem checks one system entry for unknown strategies, categories and
// combo-rule references.
func validateSystem(s System) error {
	if s.Strategy != "" && !validStrategies[s.Strategy] {
		return fmt.Errorf("config: system %q has unknown strategy %q", s.ID, s.Strategy)
	}
	for _, cat := range s.Categories {
		if !validCategories[cat] {
			return fmt.Errorf("config: system %q has unknown category %q", s.ID, cat)
		}
	}
	for _, r := range s.ComboRules {
		if err := validateComboRule(s.ID, r); err != nil {
			return err
		}
	}
	return nil
}

// validateComboRule checks one combo rule's category and requirement references.
func validateComboRule(id string, r ComboRule) error {
	if !validCategories[r.Category] {
		return fmt.Errorf("config: system %q combo rule has unknown category %q", id, r.Category)
	}
	for _, req := range r.RequiresAny {
		if !validCategories[req] {
			return fmt.Errorf("config: system %q combo rule requires unknown category %q", id, req)
		}
	}
	return nil
}

// SystemByID returns the system with the given id, or nil.
func (c *Config) SystemByID(id string) *System {
	for i := range c.Systems {
		if c.Systems[i].ID == id {
			return &c.Systems[i]
		}
	}
	return nil
}
