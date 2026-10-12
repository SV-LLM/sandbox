"""The standard-library runner for the vendored StegBrowser upstream tests fails closed.

Run: python -B tests/test_stegbrowser_upstream_runner.py   (standard library only)
"""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_stegbrowser_upstream as runner  # noqa: E402


class StandIn(unittest.TestCase):
    def test_only_raises_is_provided(self):
        stand_in = runner._stand_in()
        with self.assertRaises(AttributeError):
            stand_in.fixture
        with self.assertRaises(AttributeError):
            stand_in.mark

    def test_raises_checks_type_and_match(self):
        with runner._raises(ValueError, match="https"):
            raise ValueError("secure_url must use https")
        with self.assertRaises(AssertionError):
            with runner._raises(ValueError, match="https"):
                raise ValueError("something else")
        with self.assertRaises(AssertionError):
            with runner._raises(ValueError):
                pass
        with self.assertRaises(KeyError):
            with runner._raises(ValueError):
                raise KeyError("not the expected type")

    def test_every_upstream_test_is_collected_from_digest_verified_bytes(self):
        tests, expected = runner.suite()
        self.assertEqual(tests.countTestCases(), expected)
        self.assertEqual(expected, 19)
        self.assertEqual(sys.modules["pytest"].__doc__, runner._stand_in().__doc__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
