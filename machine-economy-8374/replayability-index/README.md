# Replayability Index — Q58

Unix/Python3.10+ dependency-free rerunnable public discovery/checker reader. Run from this folder:

```sh
python3 index_runner.py --output edition-01 --limit 14
python3 -m unittest -v test_index_runner.py
python3 -O -m unittest -v test_index_runner.py
```

The first edition explicitly covers one requested page per named directory and
14 audited URLs: original12 in round-robin order, followed by2Agent402 routes
after correcting its metadata-only pagination door to its existing route-bearing
/api/index door. That correction yielded621routes from one page, not a full catalog. Advertised terms retain original
amount/asset/payTo/network fields and units; unknown fields stay unknown.
Discovery errors and pagination/coverage facts appear in the report. Counts
describe the audited sample, never the x402 market. CDP and other doors are
unauthenticated reads only; no token or paid source is used.

Each row includes a time-stamped full production checker observation, its checked
locations, and a permalink to `/verify?url=...`. The index never fetches target
resources itself. `asserted` is not promoted to verified. Errors/refusals/rate
limits are not converted to absence. HTML escapes all external strings.

One batch is at most20 checker calls; repeated use of the same output directory
holds an OS process lock and honors a checkpoint for60seconds after batch completion.
An interrupted run leaves a one-hour crash reservation, with its exact next-attempt
time recorded; the OS lock itself releases on process exit.429 stops the batch;
no automatic retry, sleep, poller, scheduler, daemon or new host exists. The global
production limit remains authoritative. Do not evade it with alternate outputs.
Future editions reuse this runner. Output artifacts are generated observations,
not authoritative state transitions or independent chain replays.

Public inputs: ScriptMasterLabs x402-directory.json, Agora402 public discover,
x402-list and402index services, Agent402 index, CDP Bazaar resources. The source
URLs are explicit in code; a provider ignoring a pagination request is recorded
as received and not called complete. A provider-shape change produces an explicit
unrecognized condition. No catalog descriptions or proprietary datasets are copied
into source; only selected advertised facts and source-response digests are kept.

Publication target for this task is the filed JSON/HTML edition in Ecosystem KV.
Publishing on8374origin is the existing coordinator's separate leg, not performed
by this runner. NativeGoal/COSVUNBOUND; canonical source handoff:
`docs/MACHINE_ECONOMY_REPLAYABILITY_INDEX_MIRROR_HANDOFF.md`.
