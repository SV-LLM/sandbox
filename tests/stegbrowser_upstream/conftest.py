"""Run StegBrowser's own llm.v1 tests against the vendored modules.

The upstream tests import ``src.stegbrowser.<module>``. This SV-LLM/sandbox
file (not upstream) maps that name onto runtime/vendor/stegbrowser_llm so the
byte-identical upstream tests exercise the exact bytes Sandbox executes.
"""
import importlib, sys, types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime" / "vendor"))
pkg = importlib.import_module("stegbrowser_llm")
src = types.ModuleType("src")
src.__path__ = []
sys.modules.setdefault("src", src)
sys.modules["src.stegbrowser"] = pkg
for name in ("ecosystem_ephemeral", "llm_profile", "llm_browser_execution", "llm_transition"):
    sys.modules[f"src.stegbrowser.{name}"] = importlib.import_module(f"stegbrowser_llm.{name}")
