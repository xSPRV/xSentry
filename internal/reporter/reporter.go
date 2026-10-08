package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Dokuqui/xSentry/internal/scanner"
)

func ReportFindings(findings []scanner.Finding, reportUrl string) error {
	printToConsole(findings)

	if reportUrl != "" && len(findings) > 0 {
		slog.Info("sending findings report")
		if err := sendToURL(findings, reportUrl); err != nil {
			return fmt.Errorf("failed to send JSON report: %w", err)
		}
	}
	return nil
}

func printToConsole(findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "\n--- SECRETS FOUND ---")
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, "Finding:")
		fmt.Fprintf(os.Stderr, "    File:   %s\n", f.File)
		fmt.Fprintf(os.Stderr, "    Line:   %d\n", f.Line)
		fmt.Fprintf(os.Stderr, "    Rule:   %s\n", f.Details)
		if f.Commit != "" {
			fmt.Fprintf(os.Stderr, "    Commit: %s\n", f.Commit)
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "---------------------")
}

func sendToURL(findings []scanner.Finding, url string) error {
	payload := struct {
		Findings []scanner.Finding `json:"findings"`
		Count    int               `json:"count"`
	}{
		Findings: findings,
		Count:    len(findings),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned non-2xx status: %s", resp.Status)
	}

	return nil
}
