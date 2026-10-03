"""Unit tests for AST-Sentry security scanner."""

import unittest
from astsentry.analyzer import ASTAnalyzer
from astsentry.sarif import SarifReporter


class TestASTSecurityRules(unittest.TestCase):
    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_command_injection_subprocess_shell_true(self):
        code = "import subprocess\nsubprocess.run('ls -la', shell=True)\n"
        findings = self.analyzer.analyze_source(code, "test_cmd.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-101")
        self.assertEqual(findings[0].rule.cwe_id, "CWE-78")

    def test_command_injection_os_system(self):
        code = "import os\nos.system('cat /etc/passwd')\n"
        findings = self.analyzer.analyze_source(code, "test_os.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-101")

    def test_unsafe_pickle_deserialization(self):
        code = "import pickle\ndata = pickle.loads(raw_user_input)\n"
        findings = self.analyzer.analyze_source(code, "test_pickle.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-102")
        self.assertEqual(findings[0].rule.cwe_id, "CWE-502")

    def test_unsafe_yaml_load(self):
        code = "import yaml\nyaml.load(user_stream)\n"
        findings = self.analyzer.analyze_source(code, "test_yaml.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-102")

    def test_safe_yaml_load(self):
        code = "import yaml\nyaml.load(user_stream, Loader=yaml.SafeLoader)\n"
        findings = self.analyzer.analyze_source(code, "test_yaml_safe.py")
        self.assertEqual(len(findings), 0)

    def test_broken_crypto_md5(self):
        code = "import hashlib\nhashlib.md5(b'password').hexdigest()\n"
        findings = self.analyzer.analyze_source(code, "test_hash.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-103")

    def test_broken_crypto_md5_usedforsecurity_false(self):
        code = "import hashlib\nhashlib.md5(b'cache_key', usedforsecurity=False).hexdigest()\n"
        findings = self.analyzer.analyze_source(code, "test_hash_safe.py")
        self.assertEqual(len(findings), 0)

    def test_dangerous_eval(self):
        code = "eval(untrusted_code)\n"
        findings = self.analyzer.analyze_source(code, "test_eval.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-104")

    def test_hardcoded_secret(self):
        code = 'api_key = "sk_live_9817293847921837"\n'
        findings = self.analyzer.analyze_source(code, "test_secret.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-105")

    def test_insecure_tempfile(self):
        code = "import tempfile\ntempfile.mktemp()\n"
        findings = self.analyzer.analyze_source(code, "test_temp.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule.rule_id, "AS-107")

    def test_sarif_generation(self):
        code = "import os\nos.system('whoami')\n"
        findings = self.analyzer.analyze_source(code, "sarif_sample.py")
        report = SarifReporter.generate(findings)
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(len(report["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
