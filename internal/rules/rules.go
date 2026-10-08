package rules

import (
	"fmt"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/Dokuqui/xSentry/internal/console"
)

type Config struct {
	Rules []Rule `toml:"rules"`
}

type Rule struct {
	Name     string   `toml:"name"`
	Regex    string   `toml:"regex"`
	Keywords []string `toml:"keywords"`

	Entropy     float64 `toml:"entropy,omitempty"`
	SecretGroup int     `toml:"secret_group,omitempty"`

	CompiledRegex *regexp.Regexp `toml:"-"`
}

func LoadRules(filePath string) ([]Rule, error) {
	var config Config

	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, fmt.Errorf("failed to decode rules file: %w", err)
	}

	var compiledRules []Rule
	for _, r := range config.Rules {
		if r.Regex == "" {
			console.Warning(fmt.Sprintf("Skipping rule %q: regex is empty", r.Name))
			continue
		}

		compiled, err := regexp.Compile(r.Regex)
		if err != nil {
			console.Warning(fmt.Sprintf("Skipping rule %q: invalid regex: %v", r.Name, err))
			continue
		}
		if r.SecretGroup < 0 || r.SecretGroup > compiled.NumSubexp() {
			console.Warning(fmt.Sprintf("Skipping rule %q: secret_group %d is outside 0..%d", r.Name, r.SecretGroup, compiled.NumSubexp()))
			continue
		}
		r.CompiledRegex = compiled
		compiledRules = append(compiledRules, r)
	}

	return compiledRules, nil
}
