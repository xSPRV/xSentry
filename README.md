# xSentry

xSentry is a powerful, cross-platform secret scanning tool designed to prevent sensitive data (API keys, passwords,
tokens) from leaking into your source code. It can run as a local pre-commit hook to block secrets before they are
committed, or as a CI/CD step to scan your entire repository history.

## Features

* **Smart Detection:** Uses a hybrid engine combining Regular Expressions and Shannon Entropy to find both known
  patterns (like AWS keys) and unknown, random secrets.
* **Pre-Commit Hook:** Installs easily into `.git/hooks` to block secrets before they leave your machine.
* **Git-Aware:** Can scan the latest commit, the entire history, or just staged files.
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

### Option 2: Docker (Recommended for CI/CD)

Use the official Docker image to run xSentry in any CI pipeline without installing dependencies.

```bash
docker pull ghcr.io/xSPRV/xsentry:latest
docker run -v $(pwd):/src ghcr.io/xSPRV/xsentry -path=/src --scan-history
```

### Option 3: Build from Source (For Go Developers)

If you have Go 1.27+ installed:

```bash
git clone [https://github.com/xSPRV/xSentry.git](https://github.com/xSPRV/xSentry.git)
cd xSentry
go build -o xSentry ./cmd/xSentry
```

---

## Usage

### Basic Scans

### Scan the current directory (HEAD commit)

```bash
./xSentry -path="."
```

### Scan the entire commit history

```bash
./xSentry -path="." --scan-history
```

### Scan a specific file or string (via stdin)

```bash
echo "my-secret-key" | ./xSentry
# OR
cat config.yaml | ./xSentry
```

### Command Line Flags

| Flag            | Description                                    | Default              |
|:----------------|:-----------------------------------------------|:---------------------|
| `-path`         | Path to the Git repository to scan.            | `""` (stdin mode)    |
| `-scan-history` | Scan every commit in the repo's history.       | `false`              |
| `-report-url`   | URL to POST JSON findings to (for dashboards). | `""`                 |
| `-color`        | Color output: `auto`, `always`, or `never`.    | `auto`               |
| `-rules`        | Path to the TOML rules configuration file.     | `rules.example.toml` |
| `-ignore`       | Path to the ignore file.                       | `.xSentry-ignore`    |
| `-install-hook` | Install the pre-commit hook to `.git/hooks`.   | `false`              |

---

## ⚙️ Configuration

### Rules (rules.example.toml)

xSentry uses a TOML file to define detection rules. You can define simple regex rules or hybrid "Regex + Entropy" rules.

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
```

### Ignoring Secrets

**1. Inline Comments (Best Practice):** If a specific line is a false positive, add the ignore comment to the end of
that line.

```go
apiKey := "this-is-public-info-not-a-secret" // xSentry-ignore
```

**2. Global Ignore File (.xSentry-ignore):** You can ignore entire rules by adding their name to the .xSentry-ignore
file.

```plaintext
# Ignore the generic key rule globally

Generic API Key
```

---

## 🔄 CI/CD Integration

To prevent secrets from being merged, run xSentry as a blocking step in your CI pipeline.

### GitHub Actions

Add this to ``.github/workflows/security.yml``:

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
        run: xSentry -path="." --scan-history
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

If you use a central security dashboard, use the -report-url flag to send findings as JSON.

```bash
./xSentry -path="." --scan-history
--report-url="https://dashboard.internal/api/webhooks/xsentry"
```

---

## 🛡️ Security

If you find a vulnerability in xSentry itself, please open an issue or contact the maintainers directly.
