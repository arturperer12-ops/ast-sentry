"""SARIF v2.1.0 JSON generator for GitHub Security Scanning integration."""

import json
from typing import Dict, List
from .analyzer import SecurityFinding
from .rules import SECURITY_RULES


class SarifReporter:
    @staticmethod
    def generate(findings: List[SecurityFinding]) -> Dict:
        rules_dict = {}
        for r_id, r in SECURITY_RULES.items():
            rules_dict[r_id] = {
                "id": r.rule_id,
                "name": r.name,
                "shortDescription": {"text": r.name},
                "fullDescription": {"text": r.description},
                "help": {"text": f"{r.description}\nSee: {r.help_uri or ''}"},
                "properties": {
                    "tags": ["security", "vulnerability", r.cwe_id],
                    "precision": "high",
                },
                "defaultConfiguration": {
                    "level": r.severity if r.severity in ("error", "warning") else "note"
                },
            }

        results = []
        for f in findings:
            results.append({
                "ruleId": f.rule.rule_id,
                "level": f.rule.severity if f.rule.severity in ("error", "warning") else "note",
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.filename.replace("\\", "/")},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.col + 1,
                                "snippet": {"text": f.code_snippet},
                            },
                        }
                    }
                ],
            })

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ast-sentry",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/ast-sentry/ast-sentry",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_payload

    @classmethod
    def to_json(cls, findings: List[SecurityFinding], indent: int = 2) -> str:
        return json.dumps(cls.generate(findings), indent=indent)
