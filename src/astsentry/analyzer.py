"""AST-based static code analyzer implementation."""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .rules import Rule, SECURITY_RULES


@dataclass
class SecurityFinding:
    rule: Rule
    filename: str
    line: int
    col: int
    message: str
    code_snippet: str


class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[SecurityFinding] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)

        # AS-101: Command Injection (shell=True or os.system)
        if func_name in ("os.system", "os.popen"):
            self.findings.append(
                SecurityFinding(
                    rule=SECURITY_RULES["AS-101"],
                    filename=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Insecure system execution via `{func_name}`.",
                    code_snippet=self._get_snippet(node.lineno),
                )
            )
        elif func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        SecurityFinding(
                            rule=SECURITY_RULES["AS-101"],
                            filename=self.filename,
                            line=node.lineno,
                            col=node.col_offset,
                            message=f"Subprocess invoked with `shell=True` in `{func_name}`.",
                            code_snippet=self._get_snippet(node.lineno),
                        )
                    )

        # AS-102: Unsafe Deserialization
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"):
            self.findings.append(
                SecurityFinding(
                    rule=SECURITY_RULES["AS-102"],
                    filename=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Deserialization of untrusted payload via `{func_name}`.",
                    code_snippet=self._get_snippet(node.lineno),
                )
            )
        elif func_name == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_name = self._get_call_name(kw.value)
                    if "SafeLoader" in loader_name:
                        has_safe_loader = True
            if not has_safe_loader:
                self.findings.append(
                    SecurityFinding(
                        rule=SECURITY_RULES["AS-102"],
                        filename=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        message="`yaml.load` invoked without `SafeLoader`.",
                        code_snippet=self._get_snippet(node.lineno),
                    )
                )

        # AS-103: Broken Crypto (MD5/SHA1)
        if func_name in ("hashlib.md5", "hashlib.sha1"):
            used_for_sec = True
            for kw in node.keywords:
                if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    used_for_sec = False
            if used_for_sec:
                self.findings.append(
                    SecurityFinding(
                        rule=SECURITY_RULES["AS-103"],
                        filename=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"Usage of broken cryptographic hash function `{func_name}`.",
                        code_snippet=self._get_snippet(node.lineno),
                    )
                )

        # AS-104: Dynamic code execution
        if func_name in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    SecurityFinding(
                        rule=SECURITY_RULES["AS-104"],
                        filename=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"Arbitrary dynamic code execution sink `{func_name}`.",
                        code_snippet=self._get_snippet(node.lineno),
                    )
                )

        # AS-107: Insecure temp file
        if func_name == "tempfile.mktemp":
            self.findings.append(
                SecurityFinding(
                    rule=SECURITY_RULES["AS-107"],
                    filename=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    message="`tempfile.mktemp()` is inherently insecure against symlink races.",
                    code_snippet=self._get_snippet(node.lineno),
                )
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # AS-105: Hardcoded secrets
        secret_pattern = re.compile(r"^(api_key|apikey|secret|password|access_token|private_key)$", re.IGNORECASE)
        for target in node.targets:
            if isinstance(target, ast.Name) and secret_pattern.match(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) >= 8 and not val.startswith("ENV_") and not val.startswith("REPLACE_"):
                        self.findings.append(
                            SecurityFinding(
                                rule=SECURITY_RULES["AS-105"],
                                filename=self.filename,
                                line=node.lineno,
                                col=node.col_offset,
                                message=f"Hardcoded sensitive credential found in variable `{target.id}`.",
                                code_snippet=self._get_snippet(node.lineno),
                            )
                        )
        self.generic_visit(node)


class ASTAnalyzer:
    def __init__(self):
        pass

    def analyze_source(self, code: str, filename: str = "<stdin>") -> List[SecurityFinding]:
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError:
            return []
        visitor = ASTSecurityVisitor(filename, code.splitlines())
        visitor.visit(tree)
        return visitor.findings

    def analyze_file(self, filepath: Path) -> List[SecurityFinding]:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            return self.analyze_source(content, filename=str(filepath))
        except Exception:
            return []

    def scan_directory(self, target_dir: Path) -> List[SecurityFinding]:
        findings = []
        for path in target_dir.rglob("*.py"):
            # Skip hidden dirs, virtualenvs, and test directories by default
            parts = path.parts
            if any(p.startswith(".") or p in ("venv", ".venv", "env", "node_modules", "__pycache__") for p in parts):
                continue
            findings.extend(self.analyze_file(path))
        return findings
