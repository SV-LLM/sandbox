# GitHub Marketplace source components — Q56 candidate

Original request: StegVerse-Labs/.github#3443 comment7027241125.
ProjectID: MACHINE-ECONOMY-ENTRY-01 (coordination identity, not native admission).
Funding: internal source preparation; no customer engagement or Marketplace purchase.

## Built and tested

`action/` is a stdlib-only composite Action. It verifies an exact externally
supplied manifest SHA256, every member size/SHA256, exact inventory, safe paths,
and the published conformance record shape. It does not treat an in-suite
assertion as independent proof. A separately pinned, reviewed `self_check.py`
can run only with explicit `run-checker: 'true'`; this executes trusted source
on the caller's runner, not a security sandbox. The checker receives a minimal
environment and no credentials inherited through environment variables, but
retains the runner's filesystem/network permissions. Use an ephemeral runner
without credentials when checking external code. Success never means native
admission, owner binding, settlement, or production readiness.

`app/` supplies an authenticated webhook core and public network adapters for
integration into an EXISTING admitted host. It creates no listener or resident
service. HMAC is checked before effects. Durable delivery reservation is a
required host adapter, and uncertain outcomes stay reserved for reconciliation.
Installation events register only the account's owner-bound public service
origin at the public router. Billing events are recorded without granting
entitlements; pending changes never become current access. Receipt check runs
are commit-bound and neutral: publication is not independently recomputed
verification. GitHub tokens come from the existing TVC-authorized installation
adapter; no private key, webhook secret or credential is written here.

Run the local fixture tests from this directory:

```bash
python3 -I -B tests/test_components.py -v
python3 -I -B -O tests/test_components.py -v
```

## Action use and publication boundary

After review/integration, reference the Action subdirectory at a full commit
SHA. Set suite-directory to a trusted local checkout, manifest-sha256 to its
approved hash, and optionally the separately approved checker pin. Inputs are
passed through environment variables, never interpolated into shell source.
The result JSON is emitted in RUNNER_TEMP, outside the pinned suite.

The current sandbox subdirectory is a development home. GitHub Marketplace
requires a public action repository with one action metadata file at its ROOT.
The publication owner must choose the dedicated public repository and export
only action.yml, verify_suite.py, README and necessary files there. Do not add
an unrelated root action to SV-LLM/sandbox merely to bypass that requirement.
The unique Marketplace name, agreement acceptance, reviewed release/tag, and
listing submission are still owner acts. No tag or release is appropriate yet.

## App host integration still required

Bind the existing host route, existing TVC webhook-secret/installation-token
access, atomic durable delivery reservation/finish, owner account-to-public-
origin mapping, billing reconciliation and installation/repository revocation.
Adapters must retain ambiguous attempts and prohibit blind replay. The existing
host routes and authority are NOT supplied or implied by this candidate. The
manifest has an intentionally unresolved webhook URL and cannot be submitted.
Marketplace purchase events are configured on the listing webhook separately.

There is no plan activation, call-site payment, operator-route call, secret
custody, hosted framework, external resident machine, listing or deployment.
Support/contact/retention and commercial product equivalence require the
original owner's finalized policies. See listing/ and the canonical Q56 handoff.
