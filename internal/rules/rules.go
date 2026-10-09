package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

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

	Entropy      float64  `toml:"entropy,omitempty"`
	SecretGroup  int      `toml:"secret_group,omitempty"`
	ExcludePaths []string `toml:"exclude_paths,omitempty"`

	CompiledRegex        *regexp.Regexp   `toml:"-"`
	CompiledExcludePaths []*regexp.Regexp `toml:"-"`
}

func LoadRules(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %q: %w", filePath, err)
	}

	return loadRules(data)
}

func loadRules(data []byte) ([]Rule, error) {
	var config Config

	if _, err := toml.Decode(string(data), &config); err != nil {
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
		for _, pattern := range r.ExcludePaths {
			pathRegex, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %q has invalid exclude_paths pattern %q: %w", r.Name, pattern, err)
			}
			r.CompiledExcludePaths = append(r.CompiledExcludePaths, pathRegex)
		}
		r.CompiledRegex = compiled
		compiledRules = append(compiledRules, r)
	}

	return compiledRules, nil
}

func (r Rule) ExcludesPath(filePath string) bool {
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	for _, pattern := range r.CompiledExcludePaths {
		if pattern.MatchString(filePath) {
			return true
		}
	}
	return false
}
