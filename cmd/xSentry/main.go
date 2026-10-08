package main

import (
	"flag"
	"io"
	"log/slog"
	"os"

	"github.com/Dokuqui/xSentry/internal/git"
	"github.com/Dokuqui/xSentry/internal/ignore"
	"github.com/Dokuqui/xSentry/internal/reporter"
	"github.com/Dokuqui/xSentry/internal/rules"
	"github.com/Dokuqui/xSentry/internal/scanner"
)

const defaultRulesFile = "rules.example.toml"
const defaultIgnoreFile = ".xSentry-ignore"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	rulesPath := flag.String("rules", defaultRulesFile, "Path to the rules file")
	ignorePath := flag.String("ignore", defaultIgnoreFile, "Path to the ignore file")
	repoPath := flag.String("path", "", "Path to a Git repository to scan")
	scanHistory := flag.Bool("scan-history", false, "Scan all commits in history")
	installHook := flag.Bool("install-hook", false, "Install the xSentry pre-commit hook")
	scanStaged := flag.Bool("scan-staged", false, "Run in pre-commit hook mode (scans staged files)")
	reportURL := flag.String("report-url", "", "URL to POST JSON findings to")
	flag.Parse()

	if *installHook {
		err := installPreCommitHook()
		if err != nil {
			slog.Error("failed to install pre-commit hook", "error", err)
			os.Exit(1)
		}
		slog.Info("pre-commit hook installed successfully")
		os.Exit(0)
	}

	loadedRules, err := rules.LoadRules(*rulesPath)
	if err != nil {
		slog.Error("failed to load rules file", "path", *rulesPath, "error", err)
		os.Exit(2)
	}
	if len(loadedRules) == 0 {
		slog.Error("no valid rules loaded")
		os.Exit(2)
	}
	slog.Info("rules loaded", "count", len(loadedRules), "path", *rulesPath)

	ign, err := ignore.NewIgnorer(*ignorePath)
	if err != nil {
		slog.Error("failed to load ignore file", "path", *ignorePath, "error", err)
		os.Exit(2)
	}

	var allFindings []scanner.Finding
	var scanErr error

	if *scanStaged {
		slog.Info("scanning staged changes")
		patchString, err := git.GetStagedPatch()
		if err != nil {
			slog.Error("failed to get staged changes", "error", err)
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
		slog.Info("opening Git repository", "path", *repoPath)
		repo, err := git.OpenRepository(*repoPath)
		if err != nil {
			slog.Error("failed to open Git repository", "error", err)
			os.Exit(2)
		}

		if *scanHistory {
			slog.Info("scanning commit history")
			err := git.ForEachCommitPatch(repo, func(commit git.CommitPatch) error {
				findings, err := scanner.ScanPatchForCommit(commit.Patch, loadedRules, ign, commit.Hash)
				if err != nil {
					return err
				}
				allFindings = append(allFindings, findings...)
				return nil
			})
			if err != nil {
				slog.Error("history scan failed", "error", err)
				os.Exit(2)
			}
		} else {
			patchString, err := git.GetHeadPatch(repo)
			if err != nil {
				slog.Error("failed to get HEAD patch", "error", err)
				os.Exit(2)
			}
			findings, err := scanner.ScanPatch(patchString, loadedRules, ign)
			if err != nil {
				scanErr = err
			}
			allFindings = append(allFindings, findings...)
		}
	} else {
		slog.Info("scanning standard input")
		lines, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			slog.Error("failed to read standard input", "error", readErr)
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
		slog.Error("scan failed", "error", scanErr)
		os.Exit(2)
	}

	if err := reporter.ReportFindings(allFindings, *reportURL); err != nil {
		slog.Error("failed to report findings", "error", err)
		os.Exit(2)
	}

	if len(allFindings) > 0 {
		os.Exit(1)
	}

	slog.Info("scan completed with no findings")
	os.Exit(0)
}
