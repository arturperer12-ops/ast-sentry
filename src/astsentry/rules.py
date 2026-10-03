"""Security rule definitions for AST-Sentry."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str  # "error", "warning", "note"
    cwe_id: str
    help_uri: Optional[str] = None


SECURITY_RULES = {
    "AS-101": Rule(
        rule_id="AS-101",
        name="CommandInjectionRisk",
        description="Execution of system command with shell=True or uncontrolled argument string.",
        severity="error",
        cwe_id="CWE-78",
        help_uri="https://cwe.mitre.org/data/definitions/78.html",
    ),
    "AS-102": Rule(
        rule_id="AS-102",
        name="UnsafeDeserialization",
        description="Deserialization of untrusted data via pickle, shelve, or unconstrained PyYAML loader.",
        severity="error",
        cwe_id="CWE-502",
        help_uri="https://cwe.mitre.org/data/definitions/502.html",
    ),
    "AS-103": Rule(
        rule_id="AS-103",
        name="BrokenCryptoAlgorithm",
        description="Usage of broken cryptographic hash function (MD5/SHA1) without usedforsecurity=False.",
        severity="warning",
        cwe_id="CWE-328",
        help_uri="https://cwe.mitre.org/data/definitions/328.html",
    ),
    "AS-104": Rule(
        rule_id="AS-104",
        name="DangerousDynamicCodeExecution",
        description="Use of eval() or exec() with non-constant arguments allowing arbitrary code execution.",
        severity="error",
        cwe_id="CWE-95",
        help_uri="https://cwe.mitre.org/data/definitions/95.html",
    ),
    "AS-105": Rule(
        rule_id="AS-105",
        name="HardcodedCredentialDetected",
        description="Possible hardcoded secret, token, or password assigned to literal string value.",
        severity="warning",
        cwe_id="CWE-798",
        help_uri="https://cwe.mitre.org/data/definitions/798.html",
    ),
    "AS-106": Rule(
        rule_id="AS-106",
        name="InsecurePRNGForSecurity",
        description="Standard library random module used instead of cryptographically secure secrets module.",
        severity="note",
        cwe_id="CWE-338",
        help_uri="https://cwe.mitre.org/data/definitions/338.html",
    ),
    "AS-107": Rule(
        rule_id="AS-107",
        name="InsecureTempFileCreation",
        description="Use of insecure tempfile.mktemp() vulnerable to race conditions.",
        severity="error",
        cwe_id="CWE-377",
        help_uri="https://cwe.mitre.org/data/definitions/377.html",
    ),
}
