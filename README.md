# AST-Sentry

[![CI Test Suite](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)]()
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-Compliant-orange.svg)]()
[![Security: CWE Mapped](https://img.shields.io/badge/Security-CWE%20Audited-red.svg)]()

High-precision AST-based static security analyzer and vulnerability auditor designed for automated CI/CD code reviews and supply-chain risk mitigation.

---

## Key Features

* **AST-Level Semantic Inspection**: Parses code directly into Abstract Syntax Trees, avoiding regex-based false positives.
* **Native SARIF v2.1.0 Support**: Generates reports seamlessly ingestible by GitHub Code Scanning, SonarQube, and CI security dashboards.
* **Deterministic Taint & Sink Auditing**: Identifies uncontrolled sinks for command injection, unsafe deserialization, dynamic evaluation, and weak cryptography.
* **Zero External Dependencies**: Core engine operates purely on Python standard library (`ast`, `re`, `json`), minimizing attack surface in CI environments.
* **Maintainer Workflow Automation**: Designed for automated PR reviews, git pre-commit hooks, and OpenAI Codex security triage.

---

## Detection Matrix

| Rule ID | Vulnerability Class | CWE | Default Severity |
| :--- | :--- | :--- | :--- |
| **AS-101** | Command Injection (`subprocess(shell=True)`, `os.system`) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Error |
| **AS-102** | Unsafe Deserialization (`pickle`, unconstrained `yaml.load`) | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Error |
| **AS-103** | Broken Cryptographic Primitives (`MD5`/`SHA1` without non-sec flag) | [CWE-328](https://cwe.mitre.org/data/definitions/328.html) | Warning |
| **AS-104** | Dynamic Arbitrary Code Execution (`eval()`, `exec()`) | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Error |
| **AS-105** | Hardcoded Sensitive Credentials & API Keys | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Warning |
| **AS-106** | Insecure PRNG in Security Contexts | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Note |
| **AS-107** | Insecure Temporary File Creation Race Condition (`mktemp`) | [CWE-377](https://cwe.mitre.org/data/definitions/377.html) | Error |

---

## Installation

```bash
git clone https://github.com/<your-username>/ast-sentry.git
cd ast-sentry
pip install .
```

---

## Quick Usage

### 1. Scan a Target Codebase
```bash
ast-sentry ./src
```

### 2. Generate SARIF Report for GitHub Security Tab
```bash
ast-sentry ./src --sarif results.sarif --strict
```

---

## GitHub Actions CI Integration

Add `.github/workflows/security.yml` to your repository:

```yaml
name: "AST-Sentry Code Security"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  analyze:
    name: AST Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ast-sentry
        run: pip install .

      - name: Execute Security Analysis
        run: ast-sentry src --sarif results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Maintainer & Contributing Guidelines

1. All rule definitions must be backed by unit tests in `tests/`.
2. Rules must provide an explicit CWE mapping and regression test coverage.
3. PRs are validated via strict AST analysis before review approval.

---

## License

Distributed under the [MIT License](LICENSE).
