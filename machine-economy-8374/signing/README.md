> **Lane form (GEN 08, BUILD-Q-33):** a lane site runs
> `lane_signing.py` — admission by the site Authority store's
> scoped, expiring, revocable, single-use grants
> (`authority.py`), custody in the site SKAP tree. The document
> below describes the coordinator node's production form
> (`skap_signing.py`, ecosystem SKAP retrieval), retained in this
> tree as reference.

# SKAP Sign-Under-Seal Operation — BUILD-Q-14 Build

The production SKAP custody signing path for machine-economy identity
8374, built under BUILD-Q-14 (checked out on queue issue #3443, comment
6940917897; pairing mirror #3472 comment 6940923626) by the coordinator
seat (Muse) at the principal's direction, 2026-11-17. It settles the
gate the machine-economy endpoint (BUILD-Q-13) waited on:
`CUSTODY_SIGNING_PATH_NOT_SETTLED`.

Governing ruling (principal, 2026-11-16 23:52 CST): intent signing is
NOT a lesser act; every signature is custody-grade; no
policy/operational-key signing path exists. This operation is the
custody-grade path: the key material resides only in the SKAP seal and
is fetched and unsealed per signing call under governed retrieval.

## The key

- Identity **8374** (@8374; digits operative for the machine economy,
  expansion BETA). Namespace registration of 8374 is a separate
  governed act, not part of this build.
- Specimen **SKI-SIGNING_KEY-31c77c60** (StegKey definition
  `stegkey.signing_key` v1.0.0): secp256k1 keypair generated in-process
  at the birth sitting; public address (EIP-55)
  **0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be**; key fingerprint
  `31c77c60f931979498e553d5df49be008cc4702c26ea831b798cbc5b4ab73740`
  (SHA-256 of the 65-byte uncompressed public key).
- Sealed in the PP-2 production form (fresh DEK, AES-256-GCM under
  context `skap:specimen:<id>`, DEK wrapped by the TV/TVC Authority —
  operator-held KEK store outside the KV) and deposited into the
  Ecosystem KV's SKAP as deposit **seq 42**. Envelope SHA-256
  `6e6fcea3a20d8ee1657342d9848a5aa38e6d0f0601e7240f55043b1baea9db61`,
  Drive `1KoOwLkBKIMdriYHmKyxVfXleRanD4OtJ` (SKAP/Sealed); deposit
  receipt Drive `1aKfss5Rua9t0x4uMott3c1UGqb0nTm-y` (SKAP/Receipts);
  registry generation Drive `13Z0fpwVnA6bkSYNS4MGP-V5xodDdydUm`
  (SKAP/Root); birth/witness record + authorization artifact Drive
  `182btznFcJ9FjWJi6jFmhWh20Sz7UqYY3` (StegKey Registry). All stored
  size/MD5 readbacks match the local bytes.
- Custody verification at birth (PP-2 form): governed retrieval
  hash-equal; ungoverned retrieval denied `GRANT_INVALID`; plaintext
  scan — no hits. A closing workspace sweep (144 files across every
  surface this build touched; raw/hex/base64/base64url forms) found
  zero plaintext hits. Local material was destroyed at the birth
  sitting's close; the seal is the material's only residence.

## Service

- `skap_signing.py` — Python stdlib + `cryptography`, ThreadingHTTPServer
  on 127.0.0.1:8795. systemd unit `skap-signing.service`
  (`systemd/skap-signing.service`, restored by `install.sh` after VM
  replacement; the unit pins HOME/PYTHONPATH so the user-site
  `cryptography` install resolves under systemd). Watchdog:
  `skap-signing-watchdog` hook (script
  `~/hooks/scripts/skap-signing-watchdog.sh`, definition
  `~/hooks/definitions/skap-signing-watchdog.json`), registered,
  enabled, dry-run verified healthy.
- `POST /sign` — admission first (identity must be 8374;
  `payload_digest` a well-formed SHA-256 digest; `authorization_ref`
  equal to the admitted BUILD-Q-14 authorization artifact digest
  `96e78d585f3db3e0018a38dd27e8fcaf261ba9557b717f051e7c2efa6efe5658`),
  then governed SKAP retrieval per call (fresh Authority grant;
  GRANT/USAGE/RETRIEVAL receipted on the SKAP chain), ECDSA signing of
  the digest in memory (Prehashed), zeroization, and return of
  {signature (DER hex), public_address, receipt_pair}. Non-ALLOW
  carries the six-field disposition grammar plus a refusal record
  pair; nothing signs. No material is cached between calls.
- `GET /health` — status, identity/specimen, custody state, chain totals.
- `GET /replay` and `replay.py` — recompute the operation's receipt
  chain (append-only hash-chained segments under `receipts/`, patent
  spec §4 tuple form; dual-recorded pairs: operation-side +
  requester-side).

## Endpoint wiring and acceptance (2026-11-17)

The machine-economy endpoint's `POST /sign` (127.0.0.1:8794) now calls
this operation and returns its result; operation failures propagate as
FAIL_CLOSED carrying the operation's `failed_predicate`, with a
refusal pair on the endpoint chain. The endpoint gate flipped to
SETTLED only after this acceptance passed:

- (a) Specimen intent (payload SHA-256
  `0259d4587f74632b297fdce400bd21e948792c31372b66a689d6c43ea94fa348`)
  signed through the wired endpoint; the signature was verified
  INDEPENDENTLY (separate code path: hand-rolled secp256k1 key
  recovery + ECDSA equation) against 8374's public address and
  fingerprint from the birth record — VERIFIED. The operation-direct
  signature verified the same way.
- (b) Receipt pairs present on both chains; both replay MATCH
  (operation anchor after acceptance `3cf8e064…`; endpoint anchor
  `a40fc07e…`, advanced from the pre-wiring anchor `f4f862ac…` by
  exactly the acceptance pairs).
- (c) The same request without `authorization_ref` returned
  FAIL_CLOSED `AUTHORIZATION_NOT_ADMITTED` with refusal pairs on both
  chains and no signature.

## Remainders

- Carriage of SKAP chain receipts past seq 42 (verification, signing,
  and sweep crossings, seqs 43–55 at build close) to SKAP/Receipts on
  Drive — the next carriage batch; the local production tree is the
  chain of record meanwhile and replays independently.
- The StegKey definition/instance/bundle split filing
  (definitions/ + instances/ + bundles/ subfolders) — this build filed
  the combined birth/witness record at the registry root, the
  GENESIS/ACTIVATED placement.
- 8374 namespace registration (separate governed act) and public
  exposure of either service (both bind localhost only).
- Production TV/TVC form replacing the operator-held Authority store,
  on its own track (unchanged by this build).
