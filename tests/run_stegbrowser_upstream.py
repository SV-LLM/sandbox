"""Run the vendored StegBrowser llm.v1 upstream tests with the standard library only.

The four upstream test files in tests/stegbrowser_upstream are executed
byte-for-byte: each is digest-checked against
runtime/vendor/stegbrowser_llm/vendor-manifest.json before it is loaded, and
nothing in them is edited. conftest.py (SV-LLM/sandbox-authored) maps the
upstream ``src.stegbrowser`` imports onto the vendored modules, as before.

The upstream tests use one third-party name, ``pytest.raises(exc, match=...)``.
That single call is provided here by a standard-library stand-in registered as
``pytest`` for these tests only; any other ``pytest`` attribute fails closed, so
an upstream change that needs more of pytest is a test failure, not a silent
pass. Every ``test_*`` function and ``unittest.TestCase`` test in the files is
collected, and the run fails if the collected count differs from the count
parsed from the sources.

Run: python -B tests/run_stegbrowser_upstream.py   (standard library only)
"""
from __future__ import annotations
import ast, contextlib, hashlib, importlib.util, json, re, sys, types, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "tests/stegbrowser_upstream"
MANIFEST = json.loads((ROOT / "runtime/vendor/stegbrowser_llm/vendor-manifest.json").read_text())


@contextlib.contextmanager
def _raises(expected, match=None):
    try:
        yield
    except expected as exc:
        if match is not None and not re.search(match, str(exc)):
            raise AssertionError(f"{type(exc).__name__}({exc!r}) does not match {match!r}") from exc
        return
    raise AssertionError(f"DID NOT RAISE {expected}")


def _stand_in() -> types.ModuleType:
    module = types.ModuleType("pytest")
    module.__doc__ = "SV-LLM/sandbox standard-library stand-in: raises() only."
    module.raises = _raises

    def __getattr__(name):
        raise AttributeError(f"pytest.{name} is not provided by the standard-library stand-in")
    module.__getattr__ = __getattr__
    return module


def _verify_digests() -> list[Path]:
    paths = []
    for rel, expected in MANIFEST["upstream_tests"].items():
        path = ROOT / rel
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"VENDORED_UPSTREAM_TEST_DIGEST_MISMATCH: {rel}")
        paths.append(path)
    return paths


def _expected_count(path: Path) -> int:
    count = 0
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test"):
            count += 1
        elif isinstance(node, ast.ClassDef):
            count += sum(isinstance(n, ast.FunctionDef) and n.name.startswith("test") for n in node.body)
    return count


def _load(path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(f"stegbrowser_upstream_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def suite() -> tuple[unittest.TestSuite, int]:
    paths = _verify_digests()
    sys.modules["pytest"] = _stand_in()
    _load(UPSTREAM / "conftest.py")
    loader, collected, expected = unittest.TestLoader(), unittest.TestSuite(), 0
    for path in paths:
        module = _load(path)
        expected += _expected_count(path)
        collected.addTests(loader.loadTestsFromModule(module))
        for name, fn in sorted(vars(module).items()):
            if name.startswith("test") and isinstance(fn, types.FunctionType) and fn.__module__ == module.__name__:
                collected.addTest(unittest.FunctionTestCase(fn, description=f"{path.name}::{name}"))
    if collected.countTestCases() != expected:
        raise SystemExit(f"COLLECTION_MISMATCH: collected {collected.countTestCases()}, sources define {expected}")
    return collected, expected


if __name__ == "__main__":
    tests, _ = suite()
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    raise SystemExit(0 if result.wasSuccessful() else 1)
