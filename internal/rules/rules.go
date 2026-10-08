package rules

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/BurntSushi/toml"
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
			slog.Warn("skipping rule with empty regex", "rule", r.Name)
			continue
		}

		compiled, err := regexp.Compile(r.Regex)
		if err != nil {
			slog.Warn("skipping rule with invalid regex", "rule", r.Name, "error", err)
			continue
		}
		if r.SecretGroup < 0 || r.SecretGroup > compiled.NumSubexp() {
			slog.Warn("skipping rule with invalid secret_group", "rule", r.Name, "secret_group", r.SecretGroup, "capture_groups", compiled.NumSubexp())
			continue
		}
		r.CompiledRegex = compiled
		compiledRules = append(compiledRules, r)
	}

	return compiledRules, nil
}
