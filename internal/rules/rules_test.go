package rules

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestLoadDefaultRulesMatchesExample(t *testing.T) {
	defaultRules, err := LoadDefaultRules()
	if err != nil {
		t.Fatalf("LoadDefaultRules() error = %v", err)
	}
	if len(defaultRules) == 0 {
		t.Fatal("LoadDefaultRules() returned no rules")
	}

	if !containsRule(defaultRules, "AWS Access Key ID") ||
		!containsRule(defaultRules, "Terraform Variable Secret") ||
		!containsRule(defaultRules, "High Entropy String") {
		t.Fatal("built-in rules are missing expected detection rules")
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() could not locate rules_test.go")
	}
	examplePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "rules.example.toml")
	exampleRules, err := LoadRules(examplePath)
	if err != nil {
		t.Fatalf("LoadRules(%q) error = %v", examplePath, err)
	}

	if len(defaultRules) != len(exampleRules) {
		t.Fatalf("built-in rules count = %d, example rules count = %d", len(defaultRules), len(exampleRules))
	}
	for i, defaultRule := range defaultRules {
		exampleRule := exampleRules[i]
		if defaultRule.CompiledRegex == nil || exampleRule.CompiledRegex == nil {
			t.Errorf("rule %q was not compiled", defaultRule.Name)
		}
		if defaultRule.Name != exampleRule.Name ||
			defaultRule.Regex != exampleRule.Regex ||
			!reflect.DeepEqual(defaultRule.Keywords, exampleRule.Keywords) ||
			defaultRule.Entropy != exampleRule.Entropy ||
			defaultRule.SecretGroup != exampleRule.SecretGroup ||
			!reflect.DeepEqual(defaultRule.ExcludePaths, exampleRule.ExcludePaths) {
			t.Errorf("built-in rule %q differs from example rule %q", defaultRule.Name, exampleRule.Name)
		}
	}
}

func containsRule(loadedRules []Rule, name string) bool {
	for _, rule := range loadedRules {
		if rule.Name == name {
			return true
		}
	}
	return false
}
