import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import engine, security


class EngineTests(unittest.TestCase):
    def test_rule_fallback_proposes_real_fix(self):
        code = "function sumArray(arr) {\n  for (let i = 0; i <= arr.length; i++) {}\n}"
        result = engine.analyze_rules(
            "NaN sum", "loop reads past the last array index", "src/math.js", code
        )
        validated = engine.validate_patch("src/math.js", code, result["patched"])
        self.assertEqual(result["findings"][0]["rule"], "off-by-one")
        self.assertIn("i < arr.length", result["patched"])
        self.assertTrue(validated["ok"])
        self.assertIn("--- a/src/math.js", validated["diff"])

    def test_no_supported_bug_means_no_generated_patch(self):
        code = "function square(x) { return x * x; }"
        result = engine.analyze_rules("Update styling", "Change the button color", "src/ui.js", code)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["patched"], code)

    def test_llm_no_finding_cannot_supply_a_patch(self):
        code = "function square(x) { return x * x; }"

        class FakeLlm:
            @staticmethod
            def is_configured():
                return True

            @staticmethod
            def analyze(*_args):
                return {
                    "finding": False,
                    "findings": [],
                    "patched_code": "function square(x) { return 0; }",
                }

        result = engine.analyze("No issue", "", "src/math.js", code, FakeLlm())
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["patched"], code)
        self.assertFalse(result["ok"])

    def test_configured_llm_can_find_non_pattern_bug(self):
        code = "function first(items) { return items[1]; }"

        class FakeLlm:
            @staticmethod
            def is_configured():
                return True

            @staticmethod
            def analyze(*_args):
                return {
                    "finding": True,
                    "rationale": "The function returns the second element.",
                    "findings": [{
                        "rule": "wrong-index",
                        "fn": "first",
                        "line": 1,
                        "confidence": 90,
                        "why": "The first element is at index 0.",
                    }],
                    "patched_code": "function first(items) { return items[0]; }",
                }

        result = engine.analyze("Wrong first item", "Returns wrong item", "src/items.js", code, FakeLlm())
        self.assertEqual(result["provider"], "llm")
        self.assertTrue(result["ok"])
        self.assertEqual(result["patched"], "function first(items) { return items[0]; }")

    def test_rejects_protected_and_windows_traversal_paths(self):
        for path in (
            ".github/workflows/ci.yml", ".env.production", "src/../secret.js",
            r"..\backend\app.py", r"C:\repo\src\file.py", "package-lock.json",
        ):
            with self.subTest(path=path):
                self.assertFalse(engine.validate_path(path))
        self.assertTrue(engine.validate_path(r"src\math.js"))

    def test_rejects_unchanged_large_and_dangerous_patches(self):
        unchanged = engine.validate_patch("src/a.js", "const a = 1;", "const a = 1;")
        too_large = engine.validate_patch(
            "src/a.js", "old\n" * 12, "new\n" * 12
        )
        unsafe = engine.validate_patch("src/a.js", "const a = 1;", "fetch('/steal');")
        self.assertFalse(unchanged["ok"])
        self.assertFalse(too_large["ok"])
        self.assertFalse(unsafe["ok"])

    def test_patch_signature_binds_original_and_patch(self):
        token = security.patch_token("src/a.js", "before", "after")
        self.assertTrue(security.verify_token("src/a.js", "before", "after", token))
        self.assertFalse(security.verify_token("src/a.js", "changed", "after", token))
        self.assertFalse(security.verify_token("src/a.js", "before", "modified", token))


if __name__ == "__main__":
    unittest.main()
