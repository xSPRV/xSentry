package ignore

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type findingKey struct {
	commit string
	file   string
	line   int
	rule   string
}

type Ignorer struct {
	ignoredRules    map[string]bool
	ignoredFindings map[findingKey]bool
}

func NewIgnorer(filePath string) (*Ignorer, error) {
	ign := &Ignorer{
		ignoredRules:    make(map[string]bool),
		ignoredFindings: make(map[findingKey]bool),
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ign, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "finding|") {
			key, err := parseFindingEntry(line)
			if err != nil {
				return nil, fmt.Errorf("invalid finding exception %q: %w", line, err)
			}
			ign.ignoredFindings[key] = true
			continue
		}

		if !strings.Contains(line, "/") {
			ign.ignoredRules[line] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ign, nil
}

func (i *Ignorer) IsRuleIgnored(ruleName string) bool {
	return i.ignoredRules[ruleName]
}

// IsFindingIgnored checks an exact historical finding exception. A non-empty
// commit hash is required so these entries never suppress staged or range scans.
func (i *Ignorer) IsFindingIgnored(ruleName, file string, line int, commit string) bool {
	if commit == "" {
		return false
	}
	key := findingKey{
		commit: commit,
		file:   strings.ReplaceAll(file, "\\", "/"),
		line:   line,
		rule:   ruleName,
	}
	return i.ignoredFindings[key]
}

func parseFindingEntry(line string) (findingKey, error) {
	fields := strings.SplitN(line, "|", 6)
	if len(fields) != 6 {
		return findingKey{}, fmt.Errorf("expected finding|commit|file|line|rule|reason")
	}
	for index := range fields {
		fields[index] = strings.TrimSpace(fields[index])
	}
	if fields[0] != "finding" || fields[1] == "" || fields[2] == "" || fields[4] == "" || fields[5] == "" {
		return findingKey{}, fmt.Errorf("commit, file, line, rule, and reason are required")
	}
	lineNumber, err := strconv.Atoi(fields[3])
	if err != nil || lineNumber < 1 {
		return findingKey{}, fmt.Errorf("line must be a positive integer")
	}
	return findingKey{
		commit: fields[1],
		file:   strings.ReplaceAll(fields[2], "\\", "/"),
		line:   lineNumber,
		rule:   fields[4],
	}, nil
}
