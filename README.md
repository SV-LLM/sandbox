# SV-LLM Sandbox

Provider-neutral collaboration plane for SV-LLM. Sandbox admits bounded work bound to a receipted SV-LLM parent transition, assigns capabilities to registered entities, requests and records their contributions, and records a synthesis that preserves every contribution's lineage, disagreement, refusal, unavailability, failure and uncertainty.

Every attempted transition yields one receipt in this repository's transition ledger, whether it is allowed or denied, and each receipt propagates to the SV-LLM organization ledger. Sandbox-to-entity dispatch is intra-organization. Participation creates no governance authority.

Contracts: `sv-llm.sandbox-work/v0.1`, `sv-llm.contribution/v0.1`, `sv-llm.entity-capability/v0.1` and `sv-llm.capability-id/v0.1` in SV-LLM/schemas, serialized and digested under `SV_LLM_CANONICAL_JSON_V1`. Entity registration is evaluated by SV-LLM/.github `org-runtime/sandbox_registration.py` against the canonical organization tree.
