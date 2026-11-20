# Public receipt discovery — 8374 profile 0.1

This is a publication profile and a description of the current checker, not
a certification or an additional payment rule. A seller whose check reports
`NOT_FOUND_IN_CHECKED_LOCATIONS` can publish discoverable evidence as follows.

1. **Advertise routes and terms.** Return the ordinary unpaid x402 challenge
   (HTTP402 JSON or the v2 PAYMENT-REQUIRED header), and expose public JSON at
   `/.well-known/x402` and/or `/openapi.json`. State actual asset, network,
   amount and payTo; do not call a price advertisement a transaction record.
2. **Name public proof URLs explicitly in those JSON documents.** Current
   discovery walks string values and follows absolute HTTP(S) URLs whose JSON
   key path OR URL path contains replay, provenance, receipt, inspect, proof
   or verify. It follows at most three named proof URLs, one level. Relative
   links, arbitrary response headers and unspecified well-known receipt paths
   are not general proof-discovery mechanisms implemented by this checker.
   The x402 payment header advertises terms; this profile invents no receipt
   header that the checker would silently recognize.
3. **Publish the record and its reconstruction contract.** A useful public
   replay summary names verdict, pair count and nonzero64hex terminal anchor.
   A concrete discovery document can link a line-preserving export, manifest
   and standalone verifier using keys such as `proof.export_url`,
   `proof.manifest_url`, and `proof.verifier_url`. Those field names and paths
   below are RECOMMENDED profile conventions, not required universal x402 paths:

```json
{"proof":{"export_url":"https://seller.example/chain/export.ndjson",
"manifest_url":"https://seller.example/chain/manifest.json",
"verifier_url":"https://seller.example/chain/verifier.py",
"replay_url":"https://seller.example/replay"}}
```

The manifest should bind export bytes/hash, entry and pair counts, terminal
anchor, verifier hash/version and segment/genesis semantics. Retain original
line bytes; publish public data only. A customer saves the export, manifest,
verifier and independently retained anchor, then reruns the verifier offline.
Hash-chain integrity does not prove the truth of recorded assertions.

**What the existing checker actually does.** It sends unpaid GET, then POST{}
if GET does not answer402; reads the two discovery documents; follows at most
three named proof URLs and two payment-manifest links, one level; MCP-shaped
resources may receive protocol negotiation/tools-list probes. Probes use10s
timeouts,512KiB caps, at most3 revalidated GET redirects; private/loopback/
metadata targets are refused server-side. No paid crossing is performed.
Each result names its checked locations and method. Locations outside that
set are not covered by a negative result. Thirty checks/minute is the public
checker limit; refusals and rate limits are not absence.

**Evidence grades stay distinct.** `verified` means this checker recomputed
the record (currently8374's own export path); `asserted` is a seller-published
well-formed MATCH summary, not checker replay; `discovered` means record
structure/valid nonzero transaction hashes were found; `validation_failed`
means the published assertion failed checks; `none` is bounded absence.
Adding the recommended links alone does not turn a foreign seller into the
checker-recomputed class. Customer retention and independent replay remain
separate work.

**Badge semantics.** `/badge?url=<exact resource URL>` displays only the
latest cached checker's verdict and date, for300seconds. First call
`/verify/check?url=...` or use the verify page; the badge itself makes no new
check and cannot bypass the rate limit. Unknown, unprobed, refused or stale
observations render `not checked`. Cache is in-process and bounded256entries;
restart/eviction means not checked. No origin-wide conclusion is inferred
from a different resource URL. `Replay-Verified` is a rendering of the
checker's stated class, not a certificate, seller guarantee or revenue proof.

Markdown embed, after an actual check of the same resource:

```markdown
[![Replay state](https://8374.stegverse.org/badge?url=https%3A%2F%2F8374.stegverse.org%2Fcrossing)](https://8374.stegverse.org/verify?url=https%3A%2F%2F8374.stegverse.org%2Fcrossing)
```

Source candidate only until the existing origin owner publishes these routes.
