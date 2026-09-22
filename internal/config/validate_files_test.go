package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadRepoConfigs verifies the shipped config files parse and validate.
func TestLoadRepoConfigs(t *testing.T) {
	cfg, err := Load("../../configs/config.yaml")
	if err != nil {
		t.Fatalf("configs/config.yaml: %v", err)
	}
	if got := cfg.SystemByID("checker").Strategy; got != "full" {
		t.Errorf("checker strategy = %q, want full", got)
	}
	if !cfg.SystemByID("demo").AllowStrategyOverride {
		t.Errorf("demo allow_strategy_override = false, want true")
	}

	// The k8s ConfigMap embeds config.yaml under data.config.yaml.
	data, err := os.ReadFile("../../deploy/k8s/configmap.yaml")
	if err != nil {
		t.Fatalf("read configmap: %v", err)
	}
	idx := strings.Index(string(data), "config.yaml: |")
	if idx < 0 {
		t.Fatalf("configmap missing config.yaml key")
	}
	body := string(data)[idx+len("config.yaml: |"):]
	body = strings.TrimPrefix(body, "\n")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write configmap config: %v", err)
	}
	cm, err := Load(path)
	if err != nil {
		t.Fatalf("configmap config: %v", err)
	}
	if got := cm.SystemByID("checker").Strategy; got != "full" {
		t.Errorf("configmap checker strategy = %q, want full", got)
	}
}
