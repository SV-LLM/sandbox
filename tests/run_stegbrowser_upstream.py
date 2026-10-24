"""Run the vendored StegBrowser llm.v1 upstream tests with the standard library only.

The four upstream test files in tests/stegbrowser_upstream are executed
byte-for-byte: each is digest-checked against
runtime/vendor/stegbrowser_llm/vendor-manifest.json before it is loaded, and
nothing in them is edited. conftest.py (SV-LLM/sandbox-authored) maps the
upstream ``src.stegbrowser`` imports onto the vendored modules, as before.

The upstream tests are standard-library ``unittest`` tests (pytest was removed
upstream in StegVerse-Labs/StegBrowser#61), so no stand-in is installed: an
upstream test that imports pytest fails to load, which fails the run. Every
``test_*`` function and ``unittest.TestCase`` test in the files is collected,
and the run fails if the collected count differs from the count parsed from
the sources.

Run: python -B tests/run_stegbrowser_upstream.py   (standard library only)
"""
from __future__ import annotations
import ast, hashlib, importlib.util, json, sys, types, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "tests/stegbrowser_upstream"
MANIFEST = json.loads((ROOT / "runtime/vendor/stegbrowser_llm/vendor-manifest.json").read_text())


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


# The supplied epoch the upstream tests run at (NWI-S1). Upstream llm_browser_execution opens, authorizes and
# closes its lease with no `now`, so the vendored ecosystem_ephemeral would read the clock; bound by
# runtime/lease_time.py it reads this epoch's HB32 instant instead (2026-08-23T07:00:39.68Z), and the
# vendored and upstream bytes stay as pinned. Tests that pass `now=` themselves are unaffected.
SUPPLIED_HB_EPOCH = "4000"


def run() -> bool:
    tests, _ = suite()
    sys.path.insert(0, str(ROOT / "runtime"))
    import lease_time
    lease_time.bind(sys.modules["stegbrowser_llm.ecosystem_ephemeral"])
    # No run timing in the output (TextTestRunner prints "Ran N tests in Xs"): the output is a function of the head.
    stream = unittest.runner._WritelnDecorator(sys.stderr)
    result = unittest.TextTestResult(stream, True, 2)
    with lease_time.supplied(lease_time.instant(SUPPLIED_HB_EPOCH)):
        tests.run(result)
    result.printErrors()
    stream.writeln(f"Ran {result.testsRun} tests")
    stream.writeln("OK" if result.wasSuccessful() else
                   f"FAILED (failures={len(result.failures)}, errors={len(result.errors)})")
    return result.wasSuccessful()


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
