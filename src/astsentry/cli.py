"""CLI interface for AST-Sentry security scanner."""

import argparse
import sys
from pathlib import Path
from .analyzer import ASTAnalyzer
from .sarif import SarifReporter


def main():
    parser = argparse.ArgumentParser(
        prog="ast-sentry",
        description="High-precision AST static security analyzer with native SARIF output.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Directories or Python files to scan.",
    )
    parser.add_argument(
        "--sarif",
        type=str,
        default=None,
        help="Path to write SARIF report (e.g., results.sarif for GitHub Code Scanning).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero code if any security findings are discovered.",
    )

    args = parser.parse_args()
    analyzer = ASTAnalyzer()
    all_findings = []

    for target_str in args.targets:
        target = Path(target_str)
        if target.is_file():
            all_findings.extend(analyzer.analyze_file(target))
        elif target.is_dir():
            all_findings.extend(analyzer.scan_directory(target))
        else:
            print(f"[!] Warning: Target not found: {target_str}", file=sys.stderr)

    # Print summary to console
    if not all_findings:
        print("[+] AST-Sentry: No security vulnerabilities detected.")
    else:
        print(f"[!] AST-Sentry: Discovered {len(all_findings)} security finding(s):\n")
        for f in all_findings:
            sev_badge = f"[{f.rule.severity.upper()}]"
            print(f"{sev_badge:10} {f.rule.rule_id} ({f.rule.cwe_id}): {f.filename}:{f.line}:{f.col}")
            print(f"           Message: {f.message}")
            if f.code_snippet:
                print(f"           Snippet: {f.code_snippet}")
            print()

    # Write SARIF if requested
    if args.sarif:
        out_path = Path(args.sarif)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(SarifReporter.to_json(all_findings), encoding="utf-8")
        print(f"[+] SARIF report generated: {args.sarif}")

    if args.strict and any(f.rule.severity == "error" for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
