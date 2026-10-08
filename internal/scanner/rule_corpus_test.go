package scanner

import (
	"strings"
	"testing"

	"github.com/Dokuqui/xSentry/internal/rules"
)

type ruleCorpusCase struct {
	name     string
	positive string
	negative string
}

func TestRuleCorpus(t *testing.T) {
	loadedRules := loadExampleRules(t)
	cases := []ruleCorpusCase{
		{"AWS Access Key ID", joinParts("AKIA", repeat("A", 16)), joinParts("AKIA", repeat("A", 15))},
		{"AWS Secret Access Key", joinParts("aws_secret_access_key=", repeat("A", 40)), joinParts("aws_secret_access_key=", repeat("A", 39))},
		{"AWS Session Token", joinParts("aws_session_token=", repeat("A", 16)), joinParts("aws_session_token=", repeat("A", 15))},
		{"GCP API Key", joinParts("AIza", repeat("A", 35)), joinParts("AIza", repeat("A", 34))},
		{"Google OAuth Client Secret", joinParts("client_secret=\"", repeat("A", 24), "\""), joinParts("client_secret=\"", repeat("A", 23), "\"")},
		{"Google Service Account Key File", joinParts("{\"type\":\"service_", "account\"}"), joinParts("{\"type\":\"service_", "user\"}")},
		{"Azure Storage Account Key", joinParts("azure_storage_key=", repeat("A", 43)), joinParts("azure_storage_key=", repeat("A", 42))},
		{"Azure Connection String", joinParts("Account", "Key=", repeat("A", 10)), joinParts("Account", "Key=", repeat("A", 9))},
		{"GitHub PAT", joinParts("ghp_", repeat("A", 36)), joinParts("ghp_", repeat("A", 35))},
		{"GitHub OAuth", joinParts("gho_", repeat("A", 36)), joinParts("gho_", repeat("A", 35))},
		{"GitHub Refresh Token", joinParts("ghr_", repeat("A", 36)), joinParts("ghr_", repeat("A", 35))},
		{"GitLab Personal Access Token", joinParts("glpat-", repeat("A", 20)), joinParts("glpat-", repeat("A", 19))},
		{"Bitbucket App Password", joinParts("bitbucket app password=\"", repeat("A", 8), "\""), joinParts("bitbucket app password=\"", repeat("A", 7), "\"")},
		{"OAuth Access Token", joinParts("ya29.", repeat("A", 30)), joinParts("ya29.", repeat("A", 29))},
		{"Microsoft Graph Token", joinParts("Ew", repeat("A", 10), ".", repeat("B", 10)), joinParts("Ew", repeat("A", 10), repeat("B", 10))},
		{"Slack Token", joinParts("xoxb-", repeat("A", 10)), joinParts("xoxb-", repeat("A", 9))},
		{"Discord Bot Token", joinParts(repeat("A", 24), ".", repeat("B", 6), ".", repeat("C", 27)), joinParts(repeat("A", 23), ".", repeat("B", 6), ".", repeat("C", 27))},
		{"Stripe Secret Key", joinParts("sk_live_", repeat("A", 24)), joinParts("sk_live_", repeat("A", 23))},
		{"Stripe Restricted Key", joinParts("rk_live_", repeat("A", 24)), joinParts("rk_live_", repeat("A", 23))},
		{"PayPal Client Secret", joinParts(repeat("A", 20), ".", repeat("B", 20), ".", repeat("C", 10)), joinParts(repeat("A", 20), ".", repeat("B", 20), ".", repeat("C", 9))},
		{"PostgreSQL Connection String", joinParts("postgres", "://user:pass@localhost:5432/app"), joinParts("postgres", "://localhost:5432/app")},
		{"MySQL Connection String", joinParts("mysql", "://user:pass@localhost/app"), joinParts("mysql", "://localhost/app")},
		{"MongoDB Connection String", joinParts("mongodb", "://user:pass@localhost/db"), joinParts("mongodb", "://localhost/db")},
		{"Redis Connection String", joinParts("redis", "://user:pass@localhost:6379"), joinParts("redis", "://localhost:6379")},
		{"RSA Private Key", privateKeyHeader("RSA") + " PRIVATE KEY-----", privateKeyHeader("RSA") + " PUBLIC KEY-----"},
		{"OpenSSH Private Key", privateKeyHeader("OPENSSH") + " PRIVATE KEY-----", privateKeyHeader("OPENSSH") + " PUBLIC KEY-----"},
		{"DSA Private Key", privateKeyHeader("DSA") + " PRIVATE KEY-----", privateKeyHeader("DSA") + " PUBLIC KEY-----"},
		{"EC Private Key", privateKeyHeader("EC") + " PRIVATE KEY-----", privateKeyHeader("EC") + " PUBLIC KEY-----"},
		{"Bearer Token", joinParts("Bearer ", repeat("A", 20)), joinParts("Bearer ", repeat("A", 19))},
		{"Generic API Key", joinParts("api_", "key=", highEntropySample()), joinParts("api_", "key=", repeat("A", 16))},
		{"JWT Token", joinParts("eyJ", repeat("A", 10), ".", repeat("B", 10), ".", repeat("C", 10)), joinParts("eyJ", repeat("A", 10), ".", repeat("B", 10))},
		{"Hardcoded Password", joinParts("pass", "word=\"", "secret-value\""), joinParts("pass", "word=\"\"")},
		{"Username + Password Combo", joinParts("user", "name=alice; pass", "word=secret123"), joinParts("user", "name=alice")},
		{"Base64-Encoded 32-byte Key", joinParts(highEntropyBase64Sample(), "="), joinParts(repeat("A", 43), "=")},
		{"PKCS8 Private Key", privateKeyHeader("") + " PRIVATE KEY-----", privateKeyHeader("") + " PUBLIC KEY-----"},
		{"Terraform Variable Secret", joinParts("variable ", "\"db_", "password", "\" {"), joinParts("variable ", "\"db_", "name", "\" {")},
		{"Kubernetes Secret YAML", joinParts("apiVersion: v1 ", "kind: Secret"), joinParts("apiVersion: v1 ", "kind: ConfigMap")},
		{"Hardcoded GitHub Action Value", joinParts("to", "ken: \"", repeat("x", 9), "\""), joinParts("to", "ken: ${{", " secrets.API_TOKEN }}")},
		{"High Entropy String", highEntropyLongSample(), repeat("A", 52)},
	}

	if len(cases) != len(loadedRules) {
		t.Fatalf("corpus has %d cases for %d configured rules", len(cases), len(loadedRules))
	}

	rulesByName := make(map[string]rules.Rule, len(loadedRules))
	for _, rule := range loadedRules {
		rulesByName[rule.Name] = rule
	}

	seen := make(map[string]bool, len(cases))
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rule, ok := rulesByName[testCase.name]
			if !ok {
				t.Fatalf("rule %q is not present in the example configuration", testCase.name)
			}
			if seen[testCase.name] {
				t.Fatalf("rule %q has more than one corpus case", testCase.name)
			}
			seen[testCase.name] = true

			if !ruleWouldFind(rule, testCase.positive) {
				t.Errorf("positive example did not match rule %q", testCase.name)
			}
			if ruleWouldFind(rule, testCase.negative) {
				t.Errorf("negative example unexpectedly matched rule %q", testCase.name)
			}
		})
	}

	for _, rule := range loadedRules {
		if !seen[rule.Name] {
			t.Errorf("rule %q has no corpus case", rule.Name)
		}
	}
}

func ruleWouldFind(rule rules.Rule, line string) bool {
	for _, match := range rule.CompiledRegex.FindAllStringSubmatch(line, -1) {
		if rule.Entropy == 0 {
			return true
		}
		if rule.SecretGroup >= len(match) {
			continue
		}
		if calculateShannonEntropy(match[rule.SecretGroup]) > rule.Entropy {
			return true
		}
	}
	return false
}

func joinParts(parts ...string) string {
	return strings.Join(parts, "")
}

func repeat(char string, count int) string {
	return strings.Repeat(char, count)
}

func highEntropySample() string {
	return joinParts("AbCdEfGhIjKlMnOp", "QrStUvWxYz012345")
}

func highEntropyLongSample() string {
	return joinParts("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
}

func highEntropyBase64Sample() string {
	return joinParts("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopq")
}

func privateKeyHeader(kind string) string {
	if kind == "" {
		return "-----BEGIN"
	}
	return joinParts("-----BEGIN ", kind)
}
