# 8374 public chain export (CHAIN-EXPORT-01)

The cure for the convergent external-assessment finding (Gemini
F-01 / Codex F04, 2026-11-19): the receipt chain's replay verdict
was server-computed, so an external party could not recompute the
terminal anchor from exported records. This service publishes the
chain itself; the verdict becomes the evaluator's own recompute.

## Surface (public, via the proxy allowlist)

- `GET /chain` — service document (JSON)
- `GET /chain/manifest.json` — rules id (`receipt-chain-rules/1`),
  segment list, entry/pair counts, the terminal anchor the export
  must recompute to, and the verifier's URL + SHA-256 pin
- `GET /chain/export.ndjson` — every entry of the production
  endpoint receipt chain in chain order, one JSON object per line,
  the stored segment lines **verbatim** (no re-serialization, no
  redaction — the hash chain is over the stored content)
- `GET /chain/verifier.py` — `verify_chain.py`, the standalone
  stdlib-only verifier

Canonical origin: `https://8374.stegverse.org/chain`.

## Transport (measured, 2026-11-19)

The origin's Cloudflare leg truncates large single responses for
some client classes (curl and browsers receive the full stream;
naive HTTP/1.1 readers were short-read at varying points — the
GEN 12 relay-read residual class; the bore leg and localhost
deliver whole). The export therefore also answers in entry
windows (`?offset=&limit=`) and honors `Range: bytes=N-` resume.
The verifier fetches completeness-checked against the stated
Content-Length, resumes from the exact byte count held, and
falls back to windows — then recomputes over the assembled
stream. Paging and resume are transport only; a manipulated
window breaks the chain and recomputes MISMATCH.

## Discipline

- Live read of the production receipts directory at request time,
  read-only: the export serves the chain as it stands and can
  never drift from it.
- Only complete entries are served; a torn tail (BUILD-Q-16) is
  excluded and its byte count is stated in the manifest.
- Entry contents were confirmed before publication to carry no
  personal data beyond wallet addresses and ME-* scope refs —
  they are machine-economy records of insider specimens (test-bot
  labels, payment authorization digests/signatures and tx hashes
  that are already public on-chain artifacts).
- Operator surfaces stay non-public: `/replay`, `/funds`,
  `/settle-pair`, `/router/settle-pair`, `/router/replay` are not
  in the proxy allowlist.

## Files

- `chain_export.py` — the service (127.0.0.1:8799, stdlib only)
- `verify_chain.py` — the standalone verifier (single source; the
  service serves these exact bytes, hash-pinned in the manifest)
- `battery_chain_export.py` — the proof battery (export
  completeness, public recompute, tamper cases, surface sweep)
- `systemd/chain-export.service`, `install.sh` — unit + restore

## Verify it yourself

```
curl -O https://8374.stegverse.org/chain/verifier.py
python3 verify_chain.py https://8374.stegverse.org/chain
```
