# 🛡 Sentinel Core (v1.0.0)

Sentinel is an enterprise-grade AI risk scanning engine designed for EU AI Act compliance.

## Features

- **Semantic Versioning**: Strict MAJOR.MINOR.PATCH versioning.
- **Policy File Support**: Configure scan behavior via `.sentinel.yml`.
- **Path Exclusion**: Ignore directories like `node_modules/` or `vendor/` to speed up scans.
- **Multi-platform**: Native binaries for Windows, Linux, and macOS.
- **CI/CD Ready**: Integrated with GitHub Actions for automated releases and checksum verification.

## Usage

### Check Version
```bash
sentinel --version
```

### Run Scan
```bash
sentinel scan --fail-on HIGH
```

## Configuration (`.sentinel.yml`)

Create a `.sentinel.yml` file in your project root to customize Sentinel's behavior:

```yaml
# Minimum severity level to trigger a non-zero exit code
fail_on: HIGH

# List of directory patterns to exclude from scanning
exclude:
  - node_modules/
  - vendor/
  - .git/
```

> [!NOTE]  
> CLI flags (e.g., `--fail-on`) will override values specified in `.sentinel.yml`.

## Installation

Download the latest binary from the [GitHub Releases](https://github.com/moxo/sentinel/releases) page. Check the `checksums.txt` to verify binary integrity.

## Development

Sentinel is built with Rust for maximum performance and safety.

```bash
cargo build --release
```

## License

UNLICENSED — Commercial use requires an active Sentinel API subscription.
