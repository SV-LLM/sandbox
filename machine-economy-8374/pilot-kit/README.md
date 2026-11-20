# Evidence-service pilot kit — public insider specimens

This kit contains public historical specimen records, a frozen public export,
the exact published verifier, an independently recomputable expected anchor,
a caller-retention seam, and a proposed pilot offer. No customer is contacted;
no new request, payment, signature, custody operation or production change is
performed by assembling or checking this kit.

After reviewing the included Python source, run:

```sh
python3 verify_kit.py
```

The expected result is MATCH:124entries/62pairs and terminal anchor
`5513a484b9709c531143b886d47dc7d5cc75beec526ac0ffeac35d4759d64080`.
The replay disables urllib network access and uses only bundled local inputs.
Its expected anchor is pinned in KIT_MANIFEST.json and the external kit hash;
that makes the kit reproducible, not an independent attestation of the seller.
The full export is included because a middle-chain slice alone cannot replay
from GENESIS. Separate exact-line slices name the worked examples.

Read WALKTHROUGH.md, CLAIMS_BOUNDARY.md and PILOT_OFFER.md before a pilot.
The price line remains the principal's determination. The existing service
offer is distinct from a negotiated pilot price.

`pilot_integration.py` reuses the existing agent-kit result vocabulary and
one-call boundary. It accepts a caller-supplied already-authorized submission
callback and retains its original result, including refusals. It does not
create a signer or take keys. The historical source lineage is
`operation/agent-kit/receipt_client.py` at native blob
`92cb52e3003ffc997c1071698eeae89f23dea064`; its bare-key CLI and transport
fallback are NOT a new custody/retry recommendation. Use the existing admitted
successor operation for real signing/payment; this asset does not authorize it.

```python
from pilot_integration import cross_and_retain, retain_pair_from_export

# existing_admitted_agreement_call is supplied by the customer's existing agent.
# Never pass credentials in its returned dict. This wrapper calls it once.
receipt = cross_and_retain(existing_admitted_agreement_call, "customer-evidence")
# After downloading/retaining the public export and independently held anchor:
pair = retain_pair_from_export("saved-export.ndjson", receipt["pair_id"], "customer-evidence")
```

A reservation left after a transport ambiguity is reconciled through the
original call's record, never silently deleted to resubmit. A saved result or
two-line pair slice alone is not proof of chain integrity. Retain the full
export, manifest, verifier and an independently held anchor, and replay them.
Do not interpret ALLOW as permission to finalize a commercial deal or as a
guarantee of payment; the customer's own policy governs those decisions.

Source/test evidence and public historical facts are distinct from an
external customer's use, native Registry admission or current runtime truth.
Q60 native Goal/COSV remains UNBOUND; source continuation is
`docs/MACHINE_ECONOMY_PILOT_KIT_MIRROR_HANDOFF.md`.
