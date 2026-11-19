# Independent-Retention Verifier — BUILD-Q-44 (starter execution)

Customer-side verification for machine-economy receipt pairs
(identity 8374, ProjectID MACHINE-ECONOMY-ENTRY-01). Built 2026-11-17
as the starter execution of queue item BUILD-Q-44, answering finding 1
of the 2026-11-17 independent assessment: *receipt independence was
not demonstrated — a customer must be able to verify its receipt pair
after the provider is unavailable.*

## What a customer retains

A **retention bundle** (JSON, form `RETENTION_BUNDLE/1`):

- `pair` — both records of the customer's receipt pair, verbatim
  (`{i, prev, content, hash}` per record);
- `span` — every chain record from the genesis anchor through the
  pair's second member, with the anchor before the span (`GENESIS`)
  and the anchor after it (the pair's own terminal hash). The span is
  what makes the pair's predecessor linkage recomputable offline; it
  terminates **at the pair**, so appends made later cannot change the
  verdict;
- `settles` — for a settlement pair, the records of the pair it
  settles, so the settlement → crossing binding is checkable;
- `settlement_reference` — status, transaction hash, block number,
  value, asset, payee, and the payment authorization nonce, extracted
  from the pair's own settlement object;
- a header: pair id, chain name, rules version, and the provider's
  terminal anchor at export time (informational only — verification
  never uses it).

## How to verify

```
python3 verify_bundle.py bundle_pair-000020.json
```

`verify_bundle.py` is a **single standalone file**. It imports nothing
from the provider's workspace, opens no socket, and reads no file
other than the bundle. Dependencies: **Python 3 standard library
only** (hashlib, json, sys) — the chain's rules use no signatures, so
no cryptography package is needed.

It answers `VALID` (exit 0), or `INVALID` (exit 1) naming the exact
failed predicate: `HASH_MISMATCH`, `LINKAGE_BREAK`, `INDEX_GAP`,
`PAIR_STRUCTURE`, `PAIR_ANCHOR_MISMATCH`, `HELD_RECORD_DIVERGES`,
`SPAN_ANCHOR_MISMATCH`, `SETTLEMENT_REFERENCE_MISMATCH`,
`SETTLEMENT_BINDING_MISMATCH`, `NONCE_REUSE`, `SEAL_DIGEST_MISMATCH`,
`MISSING_MEMBER`, `BUNDLE_FORM_UNSUPPORTED`.

## The rules it implements (`receipt-chain-rules/1`)

Extracted from the endpoint's `ReceiptChain` / `replay` /
`seal_digest_of` and re-implemented from the bundle alone:

- **R1** record form `{i, prev, content, hash}`; indices consecutive from 1;
- **R2** canonical form `json.dumps(obj, sort_keys=True, separators=(",", ":"))` as UTF-8;
- **R3** `hash = SHA256(prev || canonical(content))`, hex;
- **R4** the first record's `prev` is `"GENESIS"`;
- **R5** every later record's `prev` equals the previous record's `hash`;
- **R6** a pair is two consecutive records sharing `pair_id`,
  `index_in_pair` 0 then 1; member 1 carries `pair_anchor` = member 0's hash;
- **R7** a payment authorization's nonce stands under exactly one pair
  in the verified span;
- **R8** sub-lane segment seals: `seal_digest = SHA256(canonical(
  {sublane, segment_index, terminal_anchor, entry_count, pair_count,
  prev_seal_digest}))` — checked when a bundle carries a seal;
  parent-chain bundles carry none.

Beyond the chain rules, the verifier binds the settlement to the
crossing: a SETTLEMENT pair must settle an ALLOW EVALUATION pair
standing in the same span, and the settlement's nonce must equal that
pair's payment authorization nonce.

## The claim demonstrated — and its bounds

Demonstrated (see `demo_transcript.json`): the bundle for the real
settled pair **PAIR-000020** (SETTLED, tx
`0x4b1dce827c08f19b3ea6aae606d5f6b473f8dcd1b055502f7c46a926e38f80b4`,
block 58730763, settling PAIR-000016) verifies **VALID** from a clean
directory with no provider contact; a one-field tamper (settlement
value) verifies **INVALID / HASH_MISMATCH**; a bundle missing its
second pair member verifies **INVALID / MISSING_MEMBER**.

Bounds, stated exactly:

- The bundle proves the pair's records are the chain's records,
  unaltered, correctly linked back to genesis, and that the
  settlement it carries is bound to the settled crossing's payment
  authorization. It does **not** by itself prove the on-chain
  settlement occurred — the transaction hash and block in the
  settlement reference are checkable against any Base chain reader,
  which is a separate, public verification.
- The span's head anchor is the chain's genesis (`GENESIS`); a
  customer who also retains a later independently witnessed anchor
  (e.g. a published terminal anchor) can pin the span against it via
  `anchor_after_span`. Anchoring the chain head to an external
  witness is outside this bundle's scope.
- **Remainder of BUILD-Q-44:** this build is the customer side plus a
  provider-side exporter run after the fact. Endpoint-side bundle
  **issuance at crossing time** — the crossing response carrying the
  customer's bundle — is not yet built; that is the item's remaining
  act.

## Files

- `verify_bundle.py` — the standalone verifier (the customer's copy).
- `export_bundle.py` — the provider-side exporter (reads the chain
  read-only; emits a bundle for a named pair).
- `bundle_pair-000020.json` — the demonstrated pair's bundle.
- `demo_transcript.json` — the demonstration record (export, clean-room
  VALID, tamper INVALID, truncation INVALID).
