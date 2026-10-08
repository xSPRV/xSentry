package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const hookContent = `#!/bin/sh
# Managed by xSentry
set -u

REPO_ROOT=$(git rev-parse --show-toplevel) || {
    echo "xSentry: could not find the repository root."
    exit 2
}

if [ -x "$REPO_ROOT/xSentry" ]; then
    XSENTRY_BINARY="$REPO_ROOT/xSentry"
elif [ -x "$REPO_ROOT/xSentry.exe" ]; then
    XSENTRY_BINARY="$REPO_ROOT/xSentry.exe"
else
    echo "xSentry: binary not found in the repository root."
    echo "Build it with: go build -o xSentry ./cmd/xSentry"
    exit 2
fi

cd "$REPO_ROOT" || exit 2
"$XSENTRY_BINARY" --scan-staged
SCAN_RESULT=$?

case "$SCAN_RESULT" in
    0)
        exit 0
        ;;
    1)
        echo "xSentry: commit blocked because a possible secret was found."
        exit 1
        ;;
    *)
        echo "xSentry: scan failed; commit blocked."
        exit 2
        ;;
esac
`

const managedHookMarker = "# Managed by xSentry"

func gitOutput(args ...string) (string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git executable not found in PATH")
	}

	cmd := exec.Command(gitPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"git %s failed: %w: %s",
			strings.Join(args, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return strings.TrimSpace(string(output)), nil
}

func resolveHooksDir() (string, error) {
	hooksDir, err := gitOutput("config", "--path", "--get", "core.hooksPath")
	if err != nil {
		hooksDir, err = gitOutput(
			"rev-parse",
			"--path-format=absolute",
			"--git-path",
			"hooks",
		)
		if err != nil {
			return "", fmt.Errorf("could not locate Git hooks directory: %w", err)
		}
	} else if !filepath.IsAbs(hooksDir) {
		root, err := gitOutput("rev-parse", "--show-toplevel")
		if err != nil {
			return "", fmt.Errorf("could not find repository root: %w", err)
		}
		hooksDir = filepath.Join(root, hooksDir)
	}

	return filepath.Clean(hooksDir), nil
}

func installPreCommitHook() error {
	hooksDir, err := resolveHooksDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("could not create hooks directory %q: %w", hooksDir, err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	info, err := os.Lstat(hookPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("existing pre-commit hook is not a regular file; leaving it unchanged")
		}

		existing, err := os.ReadFile(hookPath)
		if err != nil {
			return fmt.Errorf("could not read existing pre-commit hook: %w", err)
		}
		if !strings.Contains(string(existing), managedHookMarker) {
			return fmt.Errorf(
				"pre-commit hook already exists at %q and was left unchanged; add `xSentry --scan-staged` to it manually",
				hookPath,
			)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("could not inspect pre-commit hook: %w", err)
	}

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("could not write pre-commit hook: %w", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(hookPath, 0755); err != nil {
			return fmt.Errorf("could not make pre-commit hook executable: %w", err)
		}
	}

	return nil
}
