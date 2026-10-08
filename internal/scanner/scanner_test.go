package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Dokuqui/xSentry/internal/ignore"
	"github.com/Dokuqui/xSentry/internal/rules"
)

func TestAWSKeyLocation(t *testing.T) {
	loadedRules := loadExampleRules(t)
	patch := "" +
		"diff --git a/config.go b/config.go\n" +
		"--- a/config.go\n" +
		"+++ b/config.go\n" +
		"@@ -10,2 +10,3 @@\n" +
		" package config\n" +
		"+" + awsKeySourceLine("") + "\n" +
		" var name = \"example\"\n"

	findings, err := ScanPatch(patch, loadedRules, emptyIgnorer(t))
	if err != nil {
		t.Fatalf("ScanPatch() error = %v", err)
	}

	want := Finding{
		File:    "config.go",
		Line:    11,
		Details: "AWS Access Key ID",
	}
	if !containsFinding(findings, want) {
		t.Fatalf("ScanPatch() findings = %#v, want finding %#v", findings, want)
	}
}

func TestScanPatchIgnoresRemovedLines(t *testing.T) {
	loadedRules := loadExampleRules(t)
	patch := "" +
		"diff --git a/config.go b/config.go\n" +
		"--- a/config.go\n" +
		"+++ b/config.go\n" +
		"@@ -1 +0,0 @@\n" +
		"-" + awsKeySourceLine("") + "\n"

	findings, err := ScanPatch(patch, loadedRules, emptyIgnorer(t))
	if err != nil {
		t.Fatalf("ScanPatch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanPatch() findings = %#v, want none for a removed line", findings)
	}
}

func TestScanPatchHonorsInlineIgnore(t *testing.T) {
	loadedRules := loadExampleRules(t)
	patch := addedLinePatch("config.go", awsKeySourceLine(" // xSentry-ignore"))

	findings, err := ScanPatch(patch, loadedRules, emptyIgnorer(t))
	if err != nil {
		t.Fatalf("ScanPatch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanPatch() findings = %#v, want none for an inline-ignore line", findings)
	}
}

func TestScanPatchHonorsGlobalRuleIgnore(t *testing.T) {
	loadedRules := loadExampleRules(t)
	ignorePath := filepath.Join(t.TempDir(), ".xSentry-ignore")
	if err := os.WriteFile(ignorePath, []byte("# ignored rules\n\nAWS Access Key ID\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	ignorer, err := ignore.NewIgnorer(ignorePath)
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}

	findings, err := ScanPatch(addedLinePatch("config.go", awsKeySourceLine("")), loadedRules, ignorer)
	if err != nil {
		t.Fatalf("ScanPatch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanPatch() findings = %#v, want none for a globally ignored rule", findings)
	}
}

func TestGoSumPathExclusion(t *testing.T) {
	loadedRules := loadExampleRules(t)
	checksum := strings.Join([]string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopq"}, "")
	if len(checksum) != 43 {
		t.Fatalf("test checksum length = %d, want 43", len(checksum))
	}

	// Verify the sample would match the heuristic outside go.sum, so this test
	// specifically protects the path exclusion rather than the rule itself.
	configFindings, err := ScanPatch(addedLinePatch("config.txt", "checksum = \""+checksum+"=\""), loadedRules, emptyIgnorer(t))
	if err != nil {
		t.Fatalf("ScanPatch(config.txt) error = %v", err)
	}
	if !hasFindingForRule(configFindings, "Base64-Encoded 32-byte Key") {
		t.Fatalf("ScanPatch(config.txt) findings = %#v, want Base64-Encoded 32-byte Key", configFindings)
	}

	goSumFindings, err := ScanPatch(addedLinePatch("go.sum", "example.com/module v1.2.3 h1:"+checksum+"="), loadedRules, emptyIgnorer(t))
	if err != nil {
		t.Fatalf("ScanPatch(go.sum) error = %v", err)
	}
	if hasFindingForRule(goSumFindings, "Base64-Encoded 32-byte Key") {
		t.Fatalf("ScanPatch(go.sum) findings = %#v, want the base64 rule excluded", goSumFindings)
	}
}

func TestScanPatchForCommitIncludesCommitHash(t *testing.T) {
	loadedRules := loadExampleRules(t)
	const commit = "abc123def456"
	findings, err := ScanPatchForCommit(
		addedLinePatch("config.go", awsKeySourceLine("")),
		loadedRules,
		emptyIgnorer(t),
		commit,
	)
	if err != nil {
		t.Fatalf("ScanPatchForCommit() error = %v", err)
	}
	if !containsFinding(findings, Finding{File: "config.go", Line: 1, Details: "AWS Access Key ID", Commit: commit}) {
		t.Fatalf("ScanPatchForCommit() findings = %#v, want finding with commit %q", findings, commit)
	}
}

func loadExampleRules(t *testing.T) []rules.Rule {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() could not locate scanner_test.go")
	}
	rulesPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "rules.example.toml")
	loadedRules, err := rules.LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("LoadRules(%q) error = %v", rulesPath, err)
	}
	return loadedRules
}

func emptyIgnorer(t *testing.T) *ignore.Ignorer {
	t.Helper()
	ignorer, err := ignore.NewIgnorer(filepath.Join(t.TempDir(), ".missing-ignore-file"))
	if err != nil {
		t.Fatalf("NewIgnorer() error = %v", err)
	}
	return ignorer
}

func addedLinePatch(path, line string) string {
	return "diff --git a/" + path + " b/" + path + "\n" +
		"--- a/" + path + "\n" +
		"+++ b/" + path + "\n" +
		"@@ -0,0 +1 @@\n+" + line + "\n"
}

func awsKeySourceLine(suffix string) string {
	return `const accessKey = "` + "AKIA" + "ABCDEFGHIJKLMNOP" + `"` + suffix
}

func containsFinding(findings []Finding, want Finding) bool {
	for _, finding := range findings {
		if finding == want {
			return true
		}
	}
	return false
}

func hasFindingForRule(findings []Finding, ruleName string) bool {
	for _, finding := range findings {
		if strings.HasPrefix(finding.Details, ruleName) {
			return true
		}
	}
	return false
}
