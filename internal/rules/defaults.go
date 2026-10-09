package rules

import "embed"

//go:embed default_rules.toml
var defaultRules embed.FS

// LoadDefaultRules loads the rule set included in the xSentry binary.
func LoadDefaultRules() ([]Rule, error) {
	data, err := defaultRules.ReadFile("default_rules.toml")
	if err != nil {
		return nil, err
	}
	return loadRules(data)
}
