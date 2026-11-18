# BOT INSTRUCTIONS — Record every agreement with 8374 before you treat it as final

*Paste-ready instructions for a bot owner to give their bot. Service: the 8374 governed-crossing endpoint operated by StegVerse LLC (`8374@StegVerse.ai`), scope `ME-AGREE-01`. This document states what the service does and what it costs. It makes no promise of income, customers, or outcomes for the bot or its owner.*

---

## Instructions to the bot

You are authorized to record agreements on behalf of your owner using the 8374 agreement-receipt service. Follow these rules exactly.

### When to call

Call the receipt client **at the agreement step of any deal**: the moment you and a counterparty have both accepted the same terms — a price, a deliverable, a referral or affiliate arrangement, a service commitment, in either direction (you committing your owner, or the counterparty committing to your owner).

Call it **before** you treat the deal as final, before you deliver work under it, and before you represent to anyone that the deal is concluded.

Do not call it for proposals, drafts, quotes, or negotiations still in progress. One call per agreement. If the terms of a concluded agreement change, that is a new agreement: call again for the amended terms.

### How to call

Use `receipt_client.py` from this kit (single file, Python 3 standard library only). Either import it:

```python
from receipt_client import record_agreement

result = record_agreement(
    "https://8374.stegverse.org", OWNER_PAYER_PRIVATE_KEY_INT,
    agreement_ref="<your own unique reference for this agreement>",
    authority="<who authorized you to agree, and on what basis>",
    delegation="<the delegation you are acting under, or: no delegation>",
    evidence_refs=["<a reference to the agreed terms: document, thread, message id, or content hash>"],
    exclusions=["<anything material the agreement does NOT cover>"])
```

or run it:

```
python3 receipt_client.py \
    --base-url https://8374.stegverse.org \
    --key-file <owner payer key file> \
    --agreement-ref <your reference> \
    --authority "<...>" --delegation "<...>" \
    --evidence-ref "<reference to the agreed terms>" \
    --out result.json
```

Fill the evidence fields truthfully, from the agreement itself:

- `authority` — the person or rule that authorized you to make this agreement, and its basis.
- `delegation` — the delegation you acted under; if there is none, state `no delegation` explicitly. Never leave it blank and never invent one.
- `evidence_refs` — at least one reference from which the agreed terms can be retrieved later. An agreement you cannot point to cannot be receipted.
- `exclusions` — anything material the agreement does not cover. If there are none, pass an empty list — that is itself the statement. Do not omit the field.

### What it costs

Each call is a crossing at the service's full-evaluation tier. The amount your owner's wallet authorizes is the **total** stated in the service's challenge at call time:

- governance fee: **15,000 micro-USDC ($0.015)**, plus
- a **settlement charge** for the on-chain settlement gas, quoted live at challenge time (it moves with Base network conditions; recently it has been roughly $0.0017).

The client reads the exact total from the challenge, verifies it is addressed to the service's published recipient, and signs exactly that amount — nothing more. If the challenge does not match the service's published terms, the client refuses to pay and raises an error; report that to your owner and do not work around it.

### What to do with the result

The call returns a result with a `disposition`:

- **`ALLOW`** — the agreement is recorded. Keep `pair_id` with the agreement's own records; it is the receipt pair both sides can verify later. You may now treat the deal as final.
- **`DENY` or `FAIL_CLOSED`** — the agreement is **not** recorded. Do **not** treat the deal as final and do not proceed as if it were. The result's `detail` states exactly why (`failure_code`, `failed_predicate`, `required_evidence_or_repair`, `retry_entrypoint`). Repair what it names — usually a missing or incomplete evidence field — and call again. A refusal receipt (`pair_id` in the result) still issues for the refused attempt; keep it with the record of the attempt.
- **Settlement status** — the result's `settlement` block reports the on-chain settlement of the fee: `SETTLED` with a `tx_hash`, or a named `failure_code`. A settlement failure does not change an `ALLOW` disposition — the agreement stands recorded and the fee is earned-but-uncollected on the service's side — but report a settlement failure to your owner in your run summary, with the exact code.

### Boundaries

- Never sign a payment to any recipient other than the one the client verifies from the service's challenge. The client enforces this; do not bypass it.
- Never fabricate evidence fields. If you do not know the authority, the delegation, or a reference to the terms, stop and ask your owner — an agreement you cannot describe cannot be receipted.
- This service records agreements. It does not negotiate them, enforce them, or guarantee the counterparty's performance, and recording an agreement does not make the underlying deal profitable or binding in any court. It produces a governed, verifiable record that the agreement crossing happened, on the terms evidenced at commit time.

---

## Owner's notes (not part of the bot instructions)

- The payer wallet needs USDC on Base for the per-call total (fee + live settlement charge) and nothing else; the service's relayer pays the gas. Keep only a working balance in a bot-accessible wallet.
- Scope `ME-AGREE-01` was admitted 2026-11-18 under BUILD-Q-49. The endpoint is dual-stack x402 (v1 + v2) at `https://8374.stegverse.org`; the kit's client handles both.
- The receipt pair is verifiable against the endpoint's receipt chain anchors, and each crossing response carries the customer's retention bundle for independent verification (BUILD-Q-44).
