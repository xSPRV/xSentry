package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Dokuqui/xSentry/internal/console"
	"github.com/Dokuqui/xSentry/internal/git"
	"github.com/Dokuqui/xSentry/internal/ignore"
	"github.com/Dokuqui/xSentry/internal/reporter"
	"github.com/Dokuqui/xSentry/internal/rules"
	"github.com/Dokuqui/xSentry/internal/scanner"
)

const defaultRulesFile = "rules.example.toml"
const defaultIgnoreFile = ".xSentry-ignore"

func main() {
	rulesPath := flag.String("rules", defaultRulesFile, "Path to the rules file")
	ignorePath := flag.String("ignore", defaultIgnoreFile, "Path to the ignore file")
	repoPath := flag.String("path", "", "Path to a Git repository to scan")
	scanHistory := flag.Bool("scan-history", false, "Scan all commits in history")
	installHook := flag.Bool("install-hook", false, "Install the xSentry pre-commit hook")
	scanStaged := flag.Bool("scan-staged", false, "Run in pre-commit hook mode (scans staged files)")
	reportURL := flag.String("report-url", "", "URL to POST JSON findings to")
	colorMode := flag.String("color", "auto", "Color output: auto, always, or never")
	flag.Parse()
	if err := console.Configure(*colorMode); err != nil {
		console.Error(err.Error())
		os.Exit(2)
	}
	console.Info("xSentry")

	if *installHook {
		err := installPreCommitHook()
		if err != nil {
			console.Error("Failed to install pre-commit hook: " + err.Error())
			os.Exit(1)
		}
		console.Success("Pre-commit hook installed")
		os.Exit(0)
	}

	loadedRules, err := rules.LoadRules(*rulesPath)
	if err != nil {
		console.Error(fmt.Sprintf("Could not load rules file %q: %v", *rulesPath, err))
		os.Exit(2)
	}
	if len(loadedRules) == 0 {
		console.Error("No valid rules were loaded")
		os.Exit(2)
	}
	console.Success(fmt.Sprintf("Rules loaded: %d", len(loadedRules)))
	console.Detail("File", *rulesPath)

	ign, err := ignore.NewIgnorer(*ignorePath)
	if err != nil {
		console.Error(fmt.Sprintf("Could not load ignore file %q: %v", *ignorePath, err))
		os.Exit(2)
	}

	scanStarted := time.Now()
	var allFindings []scanner.Finding
	var scanErr error

	if *scanStaged {
		console.Progress("Scanning staged changes")
		patchString, err := git.GetStagedPatch()
		if err != nil {
			console.Error("Could not read staged changes: " + err.Error())
			os.Exit(2)
		}
		if patchString != "" {
			findings, err := scanner.ScanPatch(patchString, loadedRules, ign)
			if err != nil {
				scanErr = err
			}
			allFindings = append(allFindings, findings...)
		}

	} else if *repoPath != "" {
		console.Progress("Opening Git repository")
		console.Detail("Path", *repoPath)
		repo, err := git.OpenRepository(*repoPath)
		if err != nil {
			console.Error("Could not open Git repository: " + err.Error())
			os.Exit(2)
		}

		if *scanHistory {
			shallow, err := git.IsShallowRepository(repo)
			if err != nil {
				console.Error("Could not inspect repository history: " + err.Error())
				os.Exit(2)
			}
			if shallow {
				console.Error("Full history is unavailable in this shallow checkout")
				console.Detail("Fix", "fetch the repository with fetch-depth: 0, then rerun the scan")
				os.Exit(2)
			}
			console.Progress("Scanning full Git history")
			commitCount := 0
			err = git.ForEachCommitPatch(repo, func(commit git.CommitPatch) error {
				commitCount++
				if commitCount%100 == 0 {
					console.Progress(fmt.Sprintf("Scanned %d commits", commitCount))
				}
				findings, err := scanner.ScanPatchForCommit(commit.Patch, loadedRules, ign, commit.Hash)
				if err != nil {
					return err
				}
				allFindings = append(allFindings, findings...)
				return nil
			})
			if err != nil {
				console.Error("History scan failed: " + err.Error())
				os.Exit(2)
			}
			console.Success(fmt.Sprintf("History scanned: %d commits in %s", commitCount, time.Since(scanStarted).Round(time.Millisecond)))
		} else {
			patchString, err := git.GetHeadPatch(repo)
			if err != nil {
				console.Error("Could not read HEAD patch: " + err.Error())
				os.Exit(2)
			}
			findings, err := scanner.ScanPatch(patchString, loadedRules, ign)
			if err != nil {
				scanErr = err
			}
			allFindings = append(allFindings, findings...)
		}
	} else {
		console.Progress("Scanning standard input")
		lines, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			console.Error("Could not read standard input: " + readErr.Error())
			os.Exit(2)
		}

		if len(lines) > 0 {
			patchString := scanner.BuildFakePatch(string(lines))
			findings, err := scanner.ScanPatch(patchString, loadedRules, ign)
			if err != nil {
				scanErr = err
			}
			allFindings = append(allFindings, findings...)
		}
	}

	if scanErr != nil {
		console.Error("Scan failed: " + scanErr.Error())
		os.Exit(2)
	}

	if err := reporter.ReportFindings(allFindings, *reportURL); err != nil {
		console.Error("Could not report findings: " + err.Error())
		os.Exit(2)
	}

	if len(allFindings) > 0 {
		console.Warning(fmt.Sprintf("Scan complete: %d finding(s) in %s", len(allFindings), time.Since(scanStarted).Round(time.Millisecond)))
		os.Exit(1)
	}

	console.Success(fmt.Sprintf("Scan complete: no findings in %s", time.Since(scanStarted).Round(time.Millisecond)))
	os.Exit(0)
}
