# xSentry

xSentry is a cross-platform secret scanner for detecting credentials and other sensitive values in Git changes. It can
scan staged changes before a commit, changes between two commits in CI, the latest commit, or the full commit history.

## Features

* **Smart Detection:** Uses a hybrid engine combining Regular Expressions and Shannon Entropy to find both known
  patterns (like AWS keys) and unknown, random secrets.
* **Pre-Commit Hook:** Installs easily into `.git/hooks` to block secrets before they leave your machine.
* **Git-Aware:** Scans added lines in staged changes, a commit, a commit range, or commit history.
* **Cross-Platform:** Works seamlessly on Windows, macOS, and Linux.
* **Configurable:** Fully customizable rules and ignore lists.
* **Centralized Reporting:** Can send findings to a central dashboard via JSON/HTTP.

---

## Installation

xSentry can be installed via pre-compiled binary, Docker, or by building from source.

### Option 1: Download Binary (Recommended for Local Dev)

Perfect for Python, C#, or Node.js developers who don't have Go installed.

1. Go to the Releases page.
2. Download the archive for your OS (Windows, macOS, or Linux).
3. Extract the `xSentry` (or `xSentry.exe`) binary to your project root.

### Option 2: Docker

Use the official Docker image to run xSentry in any CI pipeline without installing dependencies.

```bash
docker pull ghcr.io/xSPRV/xsentry:latest
docker run --rm -v "$(pwd):/src" ghcr.io/xSPRV/xsentry -path=/src --scan-history
```

This scans the mounted repository's full history. For faster CI checks, use `-base` and `-head` to scan only the
changes in a push or pull request.

### Option 3: Build from Source (For Go Developers)

If you have Go 1.27+ installed:

```bash
git clone [https://github.com/xSPRV/xSentry.git](https://github.com/xSPRV/xSentry.git)
cd xSentry
go build -o xSentry ./cmd/xSentry
```

---

## Usage

### Scan modes

All Git scan modes inspect added lines in diffs. They do not scan uncommitted, unstaged working-tree changes.

#### Scan changes introduced by the latest commit

```bash
./xSentry -path="."
```

#### Scan the entire commit history

```bash
./xSentry -path="." --scan-history
```

#### Scan changes between two commits (useful for CI)

This scans lines added since the merge base of `base` and `head`. Fetch both commits before running it.

```bash
./xSentry -path="." -base="<base-sha>" -head="<head-sha>"
```

`-head` defaults to `HEAD`. Use `--scan-history` for a complete history scan; it cannot be combined with `-base`.

#### Scan staged changes

This is the mode used by the installed pre-commit hook:

```bash
./xSentry --scan-staged
```

#### Scan text from standard input

```bash
echo "my-secret-key" | ./xSentry
# OR
cat config.yaml | ./xSentry
```

### Command Line Flags

| Flag | Description | Default |
|:--|:--|:--|
| `-path` | Path to a Git repository. | `""` (read stdin) |
| `-scan-history` | Scan every commit in repository history. | `false` |
| `-base` | Base commit/ref for a range scan; requires `-path`. | `""` (disabled) |
| `-head` | Head commit/ref for a range scan. | `HEAD` |
| `-scan-staged` | Scan staged changes (used by the pre-commit hook). | `false` |
| `-install-hook` | Install xSentry's pre-commit hook in this repository. | `false` |
| `-rules` | Path to the TOML rules file. | `rules.example.toml` |
| `-ignore` | Path to the rule ignore file. | `.xSentry-ignore` |
| `-report-url` | POST findings as JSON to this URL. | `""` |
| `-color` | Color output: `auto`, `always`, or `never`. | `auto` |

`-base` cannot be combined with `--scan-history`. By default, the rules and ignore file paths are relative to the
current working directory.

### Install the pre-commit hook

Build or place the `xSentry` binary in your repository root, then run:

```bash
./xSentry -install-hook
```

The hook scans staged changes and blocks the commit when it finds a possible secret. If a pre-commit hook already
exists, xSentry leaves it unchanged; add `xSentry --scan-staged` to that hook yourself.

### Exit codes

| Code | Meaning |
|:--:|:--|
| `0` | Scan completed with no findings. |
| `1` | One or more potential secrets were found. |
| `2` | The scan could not run or report findings. |

---

## ⚙️ Configuration

### Rules (rules.example.toml)

xSentry uses a TOML file to define detection rules. You can define simple regex rules or hybrid "Regex + Entropy" rules.
Rules can also exclude file paths from that specific detector with `exclude_paths`. Each entry is a regular expression
matched against the repository-relative path, with path separators normalized to `/`.

```toml
# Simple Regex Rule

[[rules]]
name = "AWS Access Key"
regex = 'AKIA[0-9A-Z]{16}'

# Hybrid Rule (Checks Regex AND Entropy)

[[rules]]
name = "Generic API Key"
regex = 'key = "[A-Za-z0-9]{20,}"'
entropy = 4.5 # Only flag if entropy is > 4.5
exclude_paths = ['(^|/)go\.sum$'] # Do not treat Go module checksums as secrets
```

### Ignoring Secrets

**1. Inline Comments (Best Practice):** If a specific line is a false positive, add the ignore comment to the end of
that line.

```go
apiKey := "this-is-public-info-not-a-secret" // xSentry-ignore
```

**2. Global Ignore File (`.xSentry-ignore`):** Ignore a rule everywhere by adding its exact name to the file. Blank
lines and lines starting with `#` are ignored.

```plaintext
# Ignore the generic key rule globally

Generic API Key
```

---

## 🔄 CI/CD Integration

To prevent secrets from being merged, run xSentry as a blocking step in your CI pipeline.

### GitHub Actions

The repository workflow scans only the changes in pushes and pull requests. It scans full history on a manual run or weekly schedule. A range scan needs both commits available, so the checkout uses `fetch-depth: 0`.

For a custom GitHub Actions workflow, pass the pull request base and checked-out commit:

```yaml
jobs:
  xSentry:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/xSPRV/xsentry:latest
      credentials:
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Scan
        env:
          XSENTRY_BASE_SHA: ${{ github.event.pull_request.base.sha }}
          XSENTRY_HEAD_SHA: ${{ github.sha }}
        run: xSentry -path="." -base="$XSENTRY_BASE_SHA" -head="$XSENTRY_HEAD_SHA"
```

### GitLab CI

Add this to ``.gitlab-ci.yml``:

```yaml
stages:
  - security

secret_scan:
  stage: security
  image: ghcr.io/xSPRV/xsentry:latest
  script:
    - xSentry -path="." --scan-history
  allow_failure: false
```

### Azure CI

Azure pipelines often run on Windows agents. Downloading the binary is usually faster than pulling Docker on Windows.
Add
this to ``azure-pipelines.yml``:

```yaml
# azure-pipelines.yml
steps:
  - task: PowerShell@2
    displayName: "Install and Run xSentry"
    inputs:
      targetType: 'inline'
      script: |
        $url = "https://github.com/xSPRV/xSentry/releases/latest/download/xSentry_Windows_x86_64.tar.gz"
        Invoke-WebRequest -Uri $url -OutFile "xSentry.tar.gz"

        tar -xvf xSentry.tar.gz

        .\xSentry.exe -path="." --scan-history
```

### Reporting to Dashboard

If you use a central security dashboard, use `-report-url` to POST findings as JSON. xSentry sends a report only when
it finds something; the payload contains a `count` and a `findings` array.

```bash
./xSentry -path="." --scan-history \
  -report-url="https://dashboard.internal/api/webhooks/xsentry"
```

---

## 🛡️ Security

If you find a vulnerability in xSentry itself, please open an issue or contact the maintainers directly.
