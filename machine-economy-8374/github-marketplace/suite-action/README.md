# StegVerse Suite Conformance — GitHub Action source candidate

Instantiate or verify a hash-pinned StegVerse suite inside a GitHub workflow.
The Action uses the filed suite template's original `instantiate.py` and
`prove_conformance.py` unchanged, without an HTTP call or package install.
Its exit status makes an ordinary workflow check fail on a non-ALLOW result.

This is Q56's Action source leg, not the 8374 GitHub App, a Marketplace listing,
a paid service invocation, native execution authority or independent acceptance.
The App's installation, Marketplace-purchase webhook, router registration and
receipt check-run integration are a separate part of the original assignment.

## Use the source candidate

Linux/POSIX and Python 3.11 or later must already be available. No token input or
write permission is needed. Check out the repository in the normal way, then use
this directory as a local composite Action. Pin any external checkout or Action
reference to its reviewed 40-character commit SHA.

```yaml
permissions:
  contents: read
steps:
  # Check out the desired pinned source and the customer suite first.
  - name: Verify the reviewed suite
    uses: ./machine-economy-8374/github-marketplace/suite-action
    with:
      mode: verify
      suite-path: path/to/customer-suite
      manifest-sha256: REPLACE_WITH_INDEPENDENTLY_REVIEWED_64_HEX_DIGEST
```

`manifest-sha256` binds the raw bytes of `PACKAGE__MANIFEST__01.json`, not its
parsed/reformatted JSON. Keep that trust anchor in reviewed workflow code;
a digest computed from a changed suite in the same untrusted change proves
only internal consistency. The Action accepts flat, fully manifest-bound
suite directories. Every member needs a unique safe filename, integer byte
length and SHA-256. No extra files, symlinks, directories or special files.
Limits: 512 files, 2 MiB per file, 16 MiB total, 60 seconds per upstream tool.

For instantiation, author a JSON object containing the original template's
CLI variables (keys omit `--`), and review its exact SHA-256:

```yaml
- id: suite
  uses: ./machine-economy-8374/github-marketplace/suite-action
  with:
    mode: instantiate
    spec-file: machine-economy-8374/github-marketplace/suite-action/examples/instantiate.json
    spec-sha256: 783bb7efe03e4561fe698aa5a9c90affefead177e4b92b6f168cd77e3755907d
```

The included example is an UNFUNDED source-test specimen, not a registered native
Goal, customer engagement or promise of compensation. Required keys: `name`,
`generation`, `project-id`, `funding-line`, `funder`, `arrangement`, `source`,
`purpose`, `levels`, `member-title`, `body`, `pointers`, `accounts-for-errors`.
Optional keys: `suite-project-id`, `subject`, `meter-instruments`, `error-classes`,
`reading-date`, `reading-counts-json`, `compensation-line`, `prior-readings-rows`.
Every value is a string. `out`, command, checker and pricing-file overrides are
refused. Values are passed as argv to fixed tools, never interpreted by a shell.
The unchanged template enforces its own populated commercial and compensation
fields. Its filed price schedule is retained verbatim; the Action does not
check current purchase-link availability, change pricing, buy anything or
validate a live commercial entitlement.

## Results and evidence

Outputs are `verdict`, `report-path`, `result-directory`, `manifest-sha256`.
The isolated result directory in `RUNNER_TEMP` retains `result.json`, `tool.log`
and a suite copy. In verify mode the source remains byte-for-byte unchanged;
instantiation writes only the new isolated result. Retain those files using
your existing artifact mechanism if they must outlive the job.
`CONFORMANT` means the pinned upstream prover returned success against the
captured suite bytes. `FAIL_CLOSED` exits nonzero and has the six remediation
fields in the JSON report. Neither is a sovereign execution/admission result.

Only the exact supported template self-checkers can execute: GEN01 checker
`9f9207293b11f928fed46d5fe9a1a5ef41074825a90825588b97a1298bb32f7e`
and GEN02 checker
`3bdf533c44cd17f28db8ac7522f130d05bb5b1c5f2aae9d12fa91d6191f934b1`.
Custom checker bytes fail before execution even if their own manifest is
internally consistent. Python imports in upstream subprocesses exclude suite
paths. This is a restricted adapter to filed tools, not a general code sandbox.
The original prover's GEN01/GEN02 non-retroactivity and evidence limitations
are preserved; mechanical conformance does not establish substantive truth.

`SOURCE_PROVENANCE.json` pins every vendored file and the actual source archives.
The GEN02 source snapshot is explicitly
`TEMPLATE__MANIFEST__02.json` SHA-256
`b733339c719c6dd7c884a0a3c5f24b7fa347a27a9a72049dfa6d90aa04276ffa`,
not a declaration that this snapshot is the latest adopted template generation.
Changing that profile requires reviewed source and corresponding controls.

## Validate this candidate

```bash
python3 -B test_action.py -q
python3 -B -O test_action.py -q
```

The existing Sandbox workflow runs those tests and invokes the actual composite
Action twice: instantiate the pinned example, then verify its resulting suite.
No new workflow, schedule, hosted service or package dependency is introduced.

## Portable Marketplace unit and owner continuation

This directory is self-contained: copy it unchanged to a dedicated public Action
repository with `action.yml` at its root, following qualified source review and
original owner integration. Preserve `vendor/`, source provenance, tests and the
example. Marketplace name availability and the publishing account's rights have
not been authenticated. No license grant or terms acceptance is made here.
The owner must settle those facts and publish the reviewed tag/release and
Marketplace listing. Do not list the entire Sandbox or treat its subdirectory
as already discoverable in Marketplace. Proposed display name:
**StegVerse Suite Conformance**. Proposed categories: code quality / utilities.
Description: **Instantiate or verify a pinned StegVerse suite using filed template
tools; retain exact input hashes and a source-validation report in your workflow.**
The Action itself is offered as a source utility; it does not levy the 8374
per-crossing fee. Any App plan mapping is the separate Q56 App/listing leg.

Official references checked 2026-11-19:
- https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
- https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace

Canonical continuation:
[SUITE_ACTION_MIRROR_HANDOFF.md](../SUITE_ACTION_MIRROR_HANDOFF.md).
