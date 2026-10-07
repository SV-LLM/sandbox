"""SV-LLM/sandbox package wrapper for the vendored StegBrowser llm.v1 modules.

This file is authored in SV-LLM/sandbox, not copied from StegBrowser. The four
sibling modules are byte-identical to StegVerse-Labs/StegBrowser at the commit
recorded in vendor-manifest.json. Upstream's own package __init__ is not
vendored because it imports unrelated profiles (social, wallet, bridge).
"""
