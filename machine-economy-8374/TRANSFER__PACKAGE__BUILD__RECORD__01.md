# TRANSFER__PACKAGE__BUILD__RECORD__01

**Built:** 2026-11-18 (coordinator node, Muse seat — coordinator-grade starter execution at the principal's direct order, 2026-11-18 15:41 CST: build the receiving end, do not report what doesn't exist)
**ProjectID:** MACHINE-ECONOMY-ENTRY-01 · **Queue items:** BUILD-Q-24 / BUILD-Q-32 (package + proof); rides on Q-25, Q-26, Q-27, Q-35, Q-49, Q-50 as referenced
**Source of the build:** the filed handover inventory (HANDOVER__INVENTORY__MACHINE__ECONOMY__OPERATION__01, Ecosystem KV Drive `1yUWFmNMZLk1m8egQaqAJ-bzwqv7I7_Ht`) and the live operation code on the coordinator node, at the state that closed the settlement loop this morning (PAIR-000039 SETTLED; production chain 39 pairs MATCH, anchor `bdedff17d069171c355cbf8e6dbbc926eb6f7414a580b9827b029eda4646b0c5` — re-verified unchanged after this build).
**Class:** coordination/build record only — not an admission, not a lane runtime execution, not a sovereign KV write.

## What was built

`~/workspace/machine-economy-transfer/package/` — a self-contained, parameterized instantiation of the operation, assembled from the live code:

- `operation/` — endpoint.py, settlement.py (with the 2026-11-18 broadcast-failover cure), keccak_pure.py, x402_specimen.py, replay.py, relayer_setup.py, public_proxy.py, tunnel_supervisor.py, cf_tunnel_supervisor.py, connect_shim.py, carriage.py, scopes.json (ME-EVAL-01 + ME-AGREE-01), offer.base.json (offer v07), agent-kit/, and `config.template.json` (ports and the signing-operation URL are slots; offer, payTo, asset, network are the operation's published form, not slots).
- `signing/` — skap_signing.py + replay.py + README, with `config.template.json` whose custody block is entirely operator slots.
- `batteries/` — the operation's four batteries, rewired to import from this package's own `operation/` tree (no reference to the coordinator node's paths).
- `systemd/` — unit templates for all five services (endpoint, signing, public proxy, bore tunnel, Cloudflare tunnel), parameterized by prefix, tree, and ports.
- `install-all.sh` — the single bootstrap entrypoint: renders an instance tree from the package, renders both configs from templates, generates the instance's own relayer key in-tree, installs and starts the units.
- `OPERATOR__SLOTS.md` — every value a receiving site supplies, and the custody rule: **key material is born and held at the receiving site under SKAP discipline; nothing secret is in this package.** No live key, token, receipt, or chain state was copied: the coordinator's `cf-tunnel-token.txt`, `settlement_relayer.json`, `specimen_payer.json`, and the SKAP specimen were never read into the package (secret scan of the tree: clean — the tunnel token exists only as a filename reference in the supervisor code, i.e. a slot).

Package manifest: `PACKAGE__MANIFEST__01.json`, 32 members, SHA-256 `6dd5963fd59b4352ec3303027ab3c5e6fb408efcf81ef5e4cfd913b6cb46e842`. Zip: `TRANSFER__PACKAGE__01.zip`, 115,272 B, MD5 `73c0a195afc6674a23ced89e407f7d5d`.

| member | bytes | SHA-256 |
|---|---|---|
| `OPERATOR__SLOTS.md` | 3316 | `4e38f5e5653e649acdccb23a6c82b6544e6a70aacdaf326d6711119f8a30f408` |
| `README.md` | 2929 | `4fa76ee43c7351bf39c5afe677fdf32e52e198e1ad43eba314d5da1bf46766a8` |
| `batteries/agreement_battery.py` | 6982 | `5ae6dceaf89a0447065bfd7f28d5b442956317e6e79b021e74eb42c87e53fd92` |
| `batteries/settlement_battery.py` | 7088 | `d69cb4a128b0b04fde86ca384d4427add6ce84607c48eb404c8af86df28fb87f` |
| `batteries/x402_battery.py` | 9429 | `e813ed6fb43dcd3620e012824367daffd13d14a4670a6a1aa1d2721892abfb19` |
| `batteries/x402_v2_battery.py` | 10200 | `16cd5f4b7b6230b9065dfcd09f6c555a00b4d473d36bcbb34d431a5de5f61d34` |
| `install-all.sh` | 5004 | `c3e14c8e778440012fa28c8403e5a878725a3361c6cbe13e37e788ed671c9f28` |
| `operation/agent-kit/BOT__INSTRUCTIONS__01.md` | 6050 | `f6a8ca84299108d342b1e4f3c0dcaf5d04b3ad5395838bd68fc9f5fb9002629f` |
| `operation/agent-kit/receipt_client.py` | 24124 | `290b76dcff6f19edf2c6382424c6b32f87d4337ffface5cffeacbd148875234b` |
| `operation/carriage.py` | 4558 | `447e707329ff8cfdf1e977753d5c73c7fafa206724293388c1572dde45df13ae` |
| `operation/cf_tunnel_supervisor.py` | 18179 | `90f0e82928afe5d38bf0546c47ca81bd9ed0995930ab8f837a4a629145b97c0e` |
| `operation/config.template.json` | 6141 | `59bd26f3c928df918d7d6a7c1ccd8e09be7ae0e656c46296cacc15a02a4393d0` |
| `operation/connect_shim.py` | 2072 | `d2cafed1ff3f7073735f0d71af998fd5622534e9cbe058d4da18e7900fb65aeb` |
| `operation/endpoint.py` | 122513 | `641da49271581416a619aa2741b21e1d2402954d8044f7f8db494bcc1f6eacd7` |
| `operation/keccak_pure.py` | 2597 | `a666adeef5310d5db82d6b879803704bf436083c45933a2f9c3bcba96be9b0af` |
| `operation/offer.base.json` | 20107 | `2b18d98c8a3b8601c1703f1352a9a0e4646c79d5c85e37dc4e9989e49a7392b2` |
| `operation/public_proxy.py` | 14144 | `9707caea1012dd8a03c35b51b9f4535eb1ba022f5026d9019529d698eb0407ee` |
| `operation/relayer_setup.py` | 1374 | `c7cbf9076bd9d8d1c551dc92d210bcc5817f03d0eb47faf742ff1285cfe21ee9` |
| `operation/replay.py` | 731 | `8dfe1f01bcf2da7f904a13c6feebd7c0bbd80ca2de8698ac283ac3eb3399548a` |
| `operation/scopes.json` | 1306 | `c3ec95f48c1c1d6f4cbd6d38b2f1998aec20ea87a4c77c2dcf38fe0142a3e381` |
| `operation/settlement.py` | 25691 | `b0c78d08a224ed9a91fe7949972af6e1ae9e299a45c9279ce041d9c81918ad28` |
| `operation/tunnel_supervisor.py` | 6446 | `11b62560e63a339d43a031869bd9d718a8fc10d8f8804ed744cdab757ed138b5` |
| `operation/x402_specimen.py` | 4374 | `6e3fd2f6e133bcc405741fc9c22c9ddff7e91fa884069e4462497f39ae899a56` |
| `signing/README.md` | 5813 | `9af07de969aff14d1273d4b188f2ba8cbfa2fd87e74405505c161ede1606be19` |
| `signing/config.template.json` | 3003 | `082887c28bf998ce347cbe8712dc0bd8ce10fda3ce87650ad80d62049a11fc3c` |
| `signing/replay.py` | 723 | `4437758ac8da2c4e5d6260daa94b0848f9361e873486360082f86b309e00e1f9` |
| `signing/skap_signing.py` | 22605 | `fedd9b392862da2a77dc69ff5a2829afb57d3e05e042df484642c98e8d69fa9f` |
| `systemd/{{PREFIX}}-cf-tunnel.service.tmpl` | 419 | `1219aac017b8cedf94813213f6f095f971ead6603e497bd9ad366aaf3ff66544` |
| `systemd/{{PREFIX}}-endpoint.service.tmpl` | 356 | `a157e4e4c5f02f3afebe898b777f45c0a3b7aeb6bc93a22c2f6cf4964321349f` |
| `systemd/{{PREFIX}}-public-proxy.service.tmpl` | 433 | `9b8f598757d03990ee5580d365149aebfaf24737559fba685d27f570edaf054a` |
| `systemd/{{PREFIX}}-signing.service.tmpl` | 427 | `4de9ac3e4dc001d96fc3f97d3afebf76a79405e9e33cffdf7cc20e8ef8502861` |
| `systemd/{{PREFIX}}-tunnel.service.tmpl` | 353 | `f92c2045a9cd2475e3da4f1b66cfa529d8ac80cf0f5f38d2a1e250c986869169` |

## Proof — the package stood up as an independent second instance

Rendered by the package's own `install-all.sh` to `~/workspace/machine-economy-transfer/proof-instance/` (prefix `me-transfer-proof`, endpoint :8894, signing :8895, proxy :8896, own receipts dir, genesis chain). The instance's relayer was born in its own tree at bootstrap: `0x073BcC1d46e9DE1ae4851950344D33F2e98C9599`. No production state was referenced or touched at any point (production replay re-verified after teardown: MATCH, 39 pairs, anchor `bdedff17…`).

**Batteries against the instance (its own chain, unfunded instance relayer — the batteries' terms):**

- x402_battery.py — **10/10 PASS** (instance chain to 8 pairs, replay MATCH)
- x402_v2_battery.py — **8/8 PASS**
- settlement_battery.py — **5/5 PASS** (verified authorization + unfunded relayer → SETTLEMENT_RELAYER_UNFUNDED recorded, relayer named = the instance's own)
- agreement_battery.py — **5/5 PASS** (ME-AGREE-01 record-agreement ALLOW with fee/charge split in evidence)

**Settled-crossing proof (insider specimen funds only):**

- Funding: production relayer → instance relayer 0.002 ETH (tx `0xa52e7c7d3a276a3cffd57b4e76aa4bfcb14b82803dbae9889c6151692b954d6a`, block 59239801); production relayer → specimen payer ETH dust (tx `0x6a2580888da64463400850da93be15a1385b49a5b16788cf27d0ea5be1c977e6`, block 59239863); specimen payer `0xCa48d33c14d8123A00Fd2Ac386b6295C7596B0E5` → instance-born payer `0x6c770Cd5Dc744A7FdE2d1762129276A4d26fC358` exactly 20,000 µUSDC (tx `0x7945ff1b2e1bd8e4b6896f3fa612c6e458fbfe2781cd345045f82e51f57286fd`, block 59239904) — at the task's cap.
- Crossing: full-evaluation ME-EVAL-01 against the instance endpoint, signed by the instance-born payer for the live v07 challenge total 16,681 µUSDC → **ALLOW, instance PAIR-000022**. Its first settlement attempt failed closed `SETTLEMENT_RPC_UNREACHABLE` (transport intermittency, below); the designed retry entrypoint `/settle-pair` was exercised, and its first attempt broadcast the settlement (instance PAIR-000024, status SUBMITTED in the instance record — confirmation polling flaked on the same transport).
- On-chain resolution (the replayable check): tx `0xfd31b36952557ee7f4b9d564fe21e7e5adcfd658ee54690e3c714123af55b9d9` — receipt **status 0x1, block 59240288**; payTo `0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be` **46,674 → 63,355 µUSDC (+16,681, exact)**; instance payer **20,000 → 3,319 µUSDC (−16,681, exact)**. The instance submitted, through its own relayer, a settlement that landed.
- Instance final state: replay **MATCH, 27 pairs**, terminal anchor `3867313060da98e6f63c4175f8526fe09cdffed42ca878d584b8796a6b9650e0`. Instance units then disabled and removed; the rendered proof-instance tree is retained on the coordinator node as evidence.

**Transport finding (measured during the proof, service-form simulation, `env -i`):** the node's bare-proxy RPC transport is intermittent — 3 of 6 sequential `eth_getBalance` calls failed across all route combinations (primary 403 / RemoteDisconnected classes) while 3 succeeded via the publicnode fallback. This is the coordinator node's known transport shape, not a package defect: the package's settlement leg carries the same failover cure that settled PAIR-000039 in production this morning, and the instance's settlement landed through it. On a lane host with ordinary egress this predicate does not arise; it is recorded here because the proof ran on this node.

**Signing plane — exact state:** the package's signing service is complete code + templated config, and it does not start usefully until the operator fills the SKAP custody slots: with only the suite-code import slot filled (read-only import of the ecosystem SKAP suite — backbone support, no key material), the proof instance's signing service started but its health read failed on the unfilled SKAP tree slot (`key_registry.json` absent under the slot path), and it was stopped for the battery runs. Disposition in the six-field grammar:

- failure_code: `SIGNING_CUSTODY_SLOTS_UNFILLED`
- failed_predicate: the receiving site has a SKAP tree + Authority store of its own for the signing service to retrieve its sealed specimen from
- required_evidence_or_repair: the site's SKAP installation (production form = BUILD-Q-33) with the specimen born/sealed at that site; the slot list in `OPERATOR__SLOTS.md` is the complete requirement
- retry_entrypoint: fill the custody slots in the rendered `signing/config.json`, restart the signing unit, verify `/health` + an admitted `/sign` test call
- owning_goal: MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-25 + BUILD-Q-33
- next_attempt: the claiming lane's instantiation, on its own host

The crossing plane (evaluation, receipt pairs, x402 verification, settlement) does not depend on the signing slot — the endpoint's `/sign` route is the only consumer — so this bounds the signing plane only.

## What a claiming lane still must supply

1. **A host** (BUILD-Q-32): a persistent machine of its own — this package removes every other prerequisite for the crossing plane.
2. **Its own keys, born at its site:** relayer key (generated by bootstrap; fund the printed address with dust ETH on Base), and for the signing plane a SKAP-sealed specimen of its own (continuity to the operation's published address is proven through the governed retrieval path per BUILD-Q-25 — the coordinator's specimen is never transferred).
3. **Authority production form** (BUILD-Q-33) for the signing plane's TV/TVC grants.
4. **Public exposure on its own surfaces** (BUILD-Q-26): its own stable public address in `public-url.txt`; the bore form needs its `public-port.pin`, the Cloudflare form its own named tunnel + token file created in its own account.
5. **A funded payer of its own** for live crossings, and its own operation-continuity watch (BUILD-Q-27 pattern).

## Carriage

Filed to the Ecosystem KV coordination folder: this record and `TRANSFER__PACKAGE__01.zip` (identifiers in the paired queue notice, composed from the completed upload readback). Notice under BUILD-Q-24 / BUILD-Q-32 on StegVerse-Labs/.github #3443, pairing on #3472.
