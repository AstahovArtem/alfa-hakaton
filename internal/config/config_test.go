package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const validYAML = `
server:
  addr: ":8080"
  read_timeout: 5s
  write_timeout: 15s
  max_body_bytes: 2097152
  max_inflight: 512
  default_system: checker
store:
  kind: memory
  ttl: 1h
  encryption_key_env: PDN_ENC_KEY
llm:
  base_url: "https://example.com/"
  api_key_env: MODEL_KEY
  model: "deepseek-ai/DeepSeek-V4-Flash-0731"
  timeout: 60s
  stream_only: true
logging:
  level: info
  format: json
systems:
  - id: checker
    enabled: true
    strategy: partial
    unmask: true
  - id: chatbot
    enabled: true
    api_key_env: PDN_CHATBOT_KEY
    categories: [full_name, phone]
    strategy: token
    unmask: false
    combo_rules:
      - category: pin
        requires_any: [card_number]
`

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Addr != ":8080" {
		t.Errorf("addr = %q", cfg.Server.Addr)
	}
	if cfg.Server.DefaultSystem != "checker" {
		t.Errorf("default_system = %q", cfg.Server.DefaultSystem)
	}
	if len(cfg.Systems) != 2 {
		t.Errorf("systems = %d", len(cfg.Systems))
	}
	if cfg.SystemByID("chatbot") == nil {
		t.Errorf("chatbot system not found")
	}
	if cfg.SystemByID("missing") != nil {
		t.Errorf("missing system should be nil")
	}
}

func TestLoadUnknownStrategy(t *testing.T) {
	content := validYAML + "\n  - id: bad\n    enabled: true\n    strategy: nope\n"
	if _, err := Load(writeConfig(t, content)); err == nil {
		t.Errorf("expected error for unknown strategy")
	}
}

func TestLoadFullStrategyAndOverride(t *testing.T) {
	content := validYAML + `
  - id: demo
    enabled: true
    strategy: full
    allow_strategy_override: true
    unmask: true
`
	cfg, err := Load(writeConfig(t, content))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	demo := cfg.SystemByID("demo")
	if demo == nil {
		t.Fatalf("demo system not found")
	}
	if demo.Strategy != "full" {
		t.Errorf("strategy = %q, want full", demo.Strategy)
	}
	if !demo.AllowStrategyOverride {
		t.Errorf("allow_strategy_override = false, want true")
	}
	if !ValidStrategy("full") {
		t.Errorf("ValidStrategy(full) = false")
	}
	if ValidStrategy("bogus") {
		t.Errorf("ValidStrategy(bogus) = true")
	}
}

func TestLoadUnknownCategory(t *testing.T) {
	content := validYAML + "\n  - id: bad\n    enabled: true\n    categories: [not_a_category]\n"
	if _, err := Load(writeConfig(t, content)); err == nil {
		t.Errorf("expected error for unknown category")
	}
}

func TestLoadDuplicateSystem(t *testing.T) {
	content := validYAML + "\n  - id: checker\n    enabled: true\n"
	if _, err := Load(writeConfig(t, content)); err == nil {
		t.Errorf("expected error for duplicate system id")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml"); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestLoadBadStoreKind(t *testing.T) {
	content := validYAML + "\n  - id: x\n    enabled: true\n"
	content = replaceStoreKind(content, "postgres")
	if _, err := Load(writeConfig(t, content)); err == nil {
		t.Errorf("expected error for bad store kind")
	}
}

func replaceStoreKind(content, kind string) string {
	// crude: replace the store.kind line
	lines := []string{}
	for _, l := range splitLines(content) {
		if l == "  kind: memory" {
			l = "  kind: " + kind
		}
		lines = append(lines, l)
	}
	return joinLines(lines)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
