# Router scope-shape refusal repair

Existing work: BUILD-Q-54 router reliability/cure line; source finding R-GEN12-SCOPE-TYPE-01, .github#3443/7022599549 and queued7022600267. Native Goal/COSV UNBOUND; this source proposal grants no runtime or central-adoption authority.

Current source predecessor: SV-LLM/sandbox branch machine-economy-8374 at09790ed51a7de1d7a57d9f142d43e892ccd26fbd. The actual router lives at machine-economy-8374/router/router.py. The earlier operation/router.py lookup was a404; no absence inference was made.

Repair only scope-shape handling before dictionary hashing. Requests whose scope is not a string must receive the existing six-field FAIL_CLOSED disposition and a refusal pair. Missing scope defaults to receipt-only; existing string values retain existing behavior. Do not change payment verification, pricing, scope admission, routing, custody, settlement or production files.

Acceptance: isolated function and actual loopback HTTP tests for list/dict/null/bool/number values, ordinary and missing/default string scope, and chain replay in normal and optimized Python; valid requests must preserve their original downstream behavior. Publish a source PR and immutable changed-file pins, then obtain independent review and original-owner integration/central generation carry. Preserve frozen historical package manifests. No source merge, deployment or funded operation is inferred from tests.

## Implemented candidate

The `tier` mapping is reached only for string scopes. Non-string scopes reach the existing `refuse` closure under ROUTE_LOCK and emit `SCOPE_TYPE_INVALID` plus the existing six fields and one refusal pair; no payment is relayed or settled. Missing/default scope and ordinary string paths are preserved. This candidate changes only `do_route`; every other top-level function/class AST matches the pinned GEN12 router.

Executed local evidence: five unittest methods PASS in normal and optimized isolated Python, covering22 function/HTTP scenarios (8 invalid values per path, missing/default and two ordinary scope strings per path) and the resulting44-entry/22-pair chain replay MATCH. No external connections, production files, real custody, keys, payment authorization or funding were used. An existing import-time unclosed-config-file ResourceWarning is retained, not hidden or misclassified as a new defect in this repair.

Registration/handoff commit f8d0f1e82189b51686cba1d76bdf688736990adf precedes implementation on branch codex/router-scope-shape-refusals-20261119. The companion ROUTER_SCOPE_INPUT_CURE_MANIFEST__01.json pins changed payloads and explicitly excludes itself. Frozen root PACKAGE__MANIFEST__01.json and historical central suites are not rewritten. Independent review, original-owner integration, a governed central generation and deployment readback remain outstanding; no stability-version increase, production repair or release is claimed.
