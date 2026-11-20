# GitHub App and listing source components — Q56 candidate

Original request: StegVerse-Labs/.github#3443 comment7027241125.
Owning App organization: **StegVerse-org**, principal decision3443/7027442807.
ProjectID: MACHINE-ECONOMY-ENTRY-01 (coordination identity, not native admission).
Funding: internal source preparation; no customer engagement or Marketplace purchase.

## Built and tested

`app/receiver.py` supplies a bounded POST/JSON receiver adapter for the existing host, with no socket/process/listener. `app/` also supplies an authenticated webhook core and public network adapters for
integration into an EXISTING admitted host. It creates no listener or resident
service. HMAC is checked before effects. Durable delivery reservation is a
required host adapter, and uncertain outcomes stay reserved for reconciliation.
Installation events register only the account's owner-bound public service
origin at the public router. Billing events are recorded without granting
entitlements; pending changes never become current access. Receipt check runs
are commit-bound and neutral: publication is not independently recomputed
verification. GitHub tokens come from the existing TVC-authorized installation
adapter; no private key, webhook secret or credential is written here.

Run local fixture regressions:

```bash
python3 -I -B tests/test_components.py -v
python3 -I -B -O tests/test_components.py -v
```

## One Action candidate, separate App work

The original earlier Action checkout is3472/7027383800, candidatePR52. That source
packages actual suite instantiation and prove_conformance. Our later overlap was
withdrawn, not credited or independently verified. This candidate contains only
the disjoint App/webhook/receipt/listing source. The Marketplace Action requires
a separate public repository with action metadata at its root; the existing
Action author/publication owner retains that work. Preserve both candidates'
additive README sections if they integrate together.

## App host integration still required

Bind the existing host route, existing TVC webhook-secret/installation-token
access, atomic durable delivery reservation/finish, owner account-to-public-
origin mapping, billing reconciliation and installation/repository revocation.
Adapters must retain ambiguous attempts and prohibit blind replay. The existing
host routes and authority are NOT supplied or implied by this candidate. The
manifest has an intentionally unresolved webhook URL and cannot be submitted.
Marketplace purchase events are configured on the listing webhook separately.

The registration owner uses StegVerse-org's organization settings, not SV-LLM
or an individual account. Publisher verification/domain verification/listing
submission remain that org owner's acts. Original principal registration is filed at3443/7027574188: AppID5841786, publicpage https://github.com/apps/8374-governed-crossing. Webhook inactive; privatekey deliberately not generated until receiver binding. This is original-owner reported/screenshot-verified evidence, not registration performed by this code.

There is no plan activation, paid call, operator-route call, secret custody,
hosted framework, external resident machine, listing or deployment. Support,
contact, retention and commercial product equivalence require the original
owner's finalized policies. See listing/ and the canonical Q56 handoff.

## Review note O-S445-2 — 2026-11-19

When an effect fails and recording its ambiguous result also fails, the original
exception type and instance are preserved; the recording error is retained as
its cause. The delivery reservation is not released. Malformed installation
repository entries are ignored and cannot authorize check creation. Three
targeted regressions fail on the previous source and pass on this repair; the
complete local suite passes22tests in normal and optimized Python. These are
author source results, with no live effect or host/custody binding implied.
