# 8374 Verify MCP — Q57 source candidate

mcp-name: io.github.StegVerse/verify-x402-resource

One tool, `verify_x402_resource(url)`, asks the existing public checker what
evidence an x402 resource publishes. Python 3.10+; standard library only.
The MCP wrapper forwards the complete structured checker response and labels
it `CHECKER_RESPONSE_FORWARDED_NOT_WRAPPER_REPLAY`. A checker-asserted replay
stays asserted; absence stays bounded to its checked locations. Third-party
page material is untrusted data. No payments, keys, target fetches, background
jobs, new hosts or production changes occur in this wrapper.

## Run from a reviewed checkout

```sh
python3 machine-economy-8374/mcp-verify/verify_mcp.py
```

Client configuration (replace the path with the reviewed absolute checkout):

```json
{"mcpServers":{"8374-verify":{"command":"python3","args":["/absolute/reviewed/checkout/machine-economy-8374/mcp-verify/verify_mcp.py"]}}}
```

`initialize` negotiates **2025-11-25** (an explicitly supported protocol
revision, not a claim of latest-version support); then the client sends
`notifications/initialized`. `tools/list` exposes exactly one tool.
The client owns the stdio process lifetime. Only JSON-RPC appears on stdout.
No HTTP listener or resident service is created.

## Package and test

From this directory:

```sh
python3 build_package.py
python3 -m unittest -v test_verify_mcp.py
python3 -O -m unittest -v test_verify_mcp.py
python3 battery.py --package dist/stegverse-verify-mcp.pyz --output battery-live.json
```

The deterministic zipapp runs with `python3 dist/stegverse-verify-mcp.pyz`.
The dependency-free wheel installs with
`python3 -m pip install --no-index --no-deps dist/stegverse_verify_mcp-0.1.0-py3-none-any.whl`.
No package is uploaded by these commands. Installed entrypoint:
`stegverse-verify-mcp`. `dist/` is reproducibly generated, not checked in.

The packaged battery performs the MCP handshake and three sequential tool
calls. It reports `PASS` only when the actual checker returns own-origin
`verified/MATCH`, a listed target with `none` plus nonempty checked locations,
and a structured invalid-URL refusal. Non-reachability, 429, assertion-only or
changed absence produces a machine-readable non-success, never a substitute
PASS. Tests use local transport fixtures; their grade is distinct from the
live battery. A connector-fetched checker observation is separate evidence.

## Fixed upstream boundary

All calls issue one GET to `https://8374.stegverse.org/verify/check?url=...`.
The URL is query-encoded as data. No upstream endpoint override, direct target
request, redirect, automatic retry, sleep or SSRF-policy copy exists.
The production checker's SSRF and 30/min rate discipline governs. A 429 and
its Retry-After are returned without retry; clients choose later invocation.
Requests have a 120-second socket timeout, input cap 64KiB, URL cap8192 code
points and response cap4MiB. HTTP failures, malformed/oversized/non-JSON
responses and network errors are tool errors; they never become ABSENT.
The existing Python environment's normal proxy trust configuration applies.

The checker may send unpaid GET/POST probes to public target origins. The
MCP tool's readOnly annotation means no requested purchase or mutation; it
does not promise a target will ignore an unpaid request. Users should submit
public resource URLs, not confidential URLs or credentials.

## Listings and authority

`listings/server.json` follows the Official MCP Registry schema with a
proposed PyPI artifact and GitHub namespace. The wheel is built and tested
locally; public package availability and namespace ownership are **not**
established. `listings/glama.json` and `listings/smithery-listing.json` prepare
the existing-source listing inputs. They confer no registration or hosting.
Smithery's official current notice says its API, CLI, SDKs and managed
connections shut down on October31,2026; it remains a public directory.
The prepared form inputs therefore do not prescribe its retired publish
commands. Current directory acceptance of this stdio-only package must be
confirmed by the original publisher; no hosted substitute is created.

The principal/original publisher reviews the final source/evidence, confirms
namespace and distribution identity, supplies the existing repository's
license/terms determination, publishes the accepted package version, verifies
artifact/hash correspondence, and submits the prepared listings. No invented
license or newly accepted service terms are included. Submission is excluded
from Q57; a missing public package/ownership is an explicit publication
condition, not a fabricated completed listing.

Source authority: original Q57 StegVerse-Labs/.github#3443/7028977288.
Native Goal/COSV remains UNBOUND; source tests and packaging are coordination
evidence, not native admission, execution, release or an external paid use.
Canonical continuation: `docs/MACHINE_ECONOMY_MCP_VERIFY_MIRROR_HANDOFF.md`.

Primary references:

- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json
- https://www.smithery.ai/future
- https://glama.ai/blog/2025-07-08-what-is-glamajson
