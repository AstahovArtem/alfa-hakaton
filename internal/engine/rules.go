package engine

import (
	"io"

	"gopkg.in/yaml.v3"

	"pdn-shield/internal/pii"
)

// comboRuleFile is the YAML representation of a combo rule.
type comboRuleFile struct {
	Category    pii.Category   `yaml:"category"`
	RequiresAny []pii.Category `yaml:"requires_any"`
}

// LoadComboRules parses combo rules from r.
func LoadComboRules(r io.Reader) ([]ComboRule, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var rules []comboRuleFile
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	out := make([]ComboRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ComboRule{Category: r.Category, RequiresAny: r.RequiresAny})
	}
	return out, nil
}
