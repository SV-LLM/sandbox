# A retained evidence loop, using public insider specimens

All worked records below are operator-funded INSIDER SPECIMENS, not external
customers or proof of demand. They were already on the public production
chain; this kit sends no transaction or new crossing.

1. In a real pilot, an independently operated agent submits a request through
   its existing authorized caller after inspecting the live x402 challenge.
   It checks network/asset/payTo/amount and its authority at the action.
   An unpaid challenge is an advertisement, not completed work or a payment.
   The existing agent-kit agreement lineage supplies the result vocabulary;
   `pilot_integration.py` adds durable caller retention without signing or retries.
2. The recorded decision issues as a matched pair. Historical PAIR-000016 is
   an ALLOW evaluation under ME-EVAL-01. Its initial settlement attempt failed;
   the original decision is not rewritten to make that failure disappear.
3. PAIR-000020 explicitly names settles_pair_id=PAIR-000016 and records
   SETTLED with tx
   `0x4b1dce827c08f19b3ea6aae606d5f6b473f8dcd1b055502f7c46a926e38f80b4`,
   block58730763. PAIR-000021 and later PAIR-000023 provide the analogous
   public-path specimen. These are recorded assertions and public transaction
   identifiers; this kit does not query a blockchain node to certify them.
4. PAIR-000040 is an agreement specimen for `specimenworks-framework`,
   action record-agreement/scope ME-AGREE-01; later PAIR-000044 names its
   settlement. Inspect the exact retained lines in bundle/examples.ndjson.
   The counterparty label is a specimen label, not independent identity proof.
5. A real customer retains the original caller response AND its matched
   pair, then downloads/holds the full public export, manifest, verifier and
   an anchor obtained/retained independently of a later provider response.
   This kit freezes that evidence set at124entries/62pairs. Exact-line slices
   preserve provenance; the complete prefix is included for reconstruction.
6. Run `python3 verify_kit.py`. It checks every kit member's size/hash, verifies
   the published verifier digest and export length, disables network access,
   and executes the unchanged verifier on local inputs. The demonstration
   reproduces MATCH and the expected terminal anchor while network requests
   are refused. It demonstrates retained-input replay, not an actual provider outage.
7. Change one byte in a copied record: the kit byte check refuses it. The
   published verifier also reports a changed record/hash mismatch when tested
   directly against the original retained anchor. Source logs retain the actual
   positive and tamper outcomes. Never edit the frozen original evidence.

For a REAL external pilot, the receiving customer must independently retain
and replay its OWN resulting records. That is still unproven by these insider
specimens. Payment outcome, record integrity, assertion truth, customer demand
and profitability are separate propositions; see CLAIMS_BOUNDARY.md.
