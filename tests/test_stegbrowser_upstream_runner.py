"""The standard-library runner for the vendored StegBrowser upstream tests fails closed.

Run: python -B tests/test_stegbrowser_upstream_runner.py   (standard library only)
"""
import ast, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_stegbrowser_upstream as runner  # noqa: E402


class Runner(unittest.TestCase):
    def test_no_vendored_upstream_test_imports_pytest(self):
        for path in runner._verify_digests():
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                         else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                self.assertFalse(any(n.split(".")[0] == "pytest" for n in names), path.name)

    def test_every_upstream_test_is_collected_from_digest_verified_bytes(self):
        tests, expected = runner.suite()
        self.assertEqual(tests.countTestCases(), expected)
        self.assertEqual(expected, 25)
        self.assertNotIn("pytest", sys.modules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
