package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Dokuqui/xSentry/internal/console"
	"github.com/Dokuqui/xSentry/internal/scanner"
)

func ReportFindings(findings []scanner.Finding, reportUrl string) error {
	printToConsole(findings)

	if reportUrl != "" && len(findings) > 0 {
		console.Progress("Sending findings report")
		if err := sendToURL(findings, reportUrl); err != nil {
			return fmt.Errorf("failed to send JSON report: %w", err)
		}
		console.Success("Findings report sent")
	}
	return nil
}

func printToConsole(findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	console.Warning(fmt.Sprintf("%d potential secret finding(s)", len(findings)))
	for _, f := range findings {
		console.Error("Potential secret")
		console.Detail("File", f.File)
		console.Detail("Line", fmt.Sprint(f.Line))
		console.Detail("Rule", f.Details)
		if f.Commit != "" {
			console.Detail("Commit", f.Commit)
		}
	}
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
