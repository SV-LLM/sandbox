#!/usr/bin/env python3
"""8374 agreement-receipt client — the bot kit caller (BUILD-Q-49).

A single-file, standard-library-only drop-in for an agent / bot
workflow. When the bot reaches an agreement (deal terms accepted by
both sides), it calls ONE function — record_agreement() — BEFORE
treating the deal as final. The function performs a governed
crossing against the 8374 endpoint under the admitted scope
ME-AGREE-01 (action "record-agreement", full-evaluation tier):

  1. POST /crossing unpaid -> the x402 challenge (dual-stack: a v1
     body and, when offered, the v2 PAYMENT-REQUIRED header). The
     challenge amount is the TOTAL authorized for the crossing:
     the full-evaluation governance fee (15,000 micro-USDC) PLUS
     the settlement charge quoted at challenge time from live Base
     gas conditions (the principal's BUILD-Q-43 determination:
     settlement gas is an additional charge on the crossing, never
     absorbed by the service).
  2. The client validates the challenge against the expected
     receptor constants below (network / asset / payTo / scheme,
     and the governance-fee split). It refuses to pay anything
     that does not match — the payee is verified client-side,
     never trusted blind.
  3. It signs an EIP-3009 transferWithAuthorization (EIP-712 under
     the USDC domain on Base) for exactly the quoted total,
     single-use nonce, and presents it as PAYMENT-SIGNATURE
     (x402 v2) when the challenge carried the v2 header, else
     X-PAYMENT (v1).
  4. It returns the outcome as a plain dict: the disposition
     (ALLOW / DENY / FAIL_CLOSED), the receipt-pair id, the fee /
     settlement-charge split, and the settlement record (status,
     tx hash, or the exact failure code).

On ALLOW, the receipt pair is the bot's portable proof of the
agreement crossing: either side can verify it later against the
chain's anchors. On NON-ALLOW, the returned dict carries the
six-field disposition (failure_code, failed_predicate,
required_evidence_or_repair, retry_entrypoint, owning_goal,
next_attempt) so the bot can repair and retry, and a refusal
receipt pair still issues for the attempt.

The signing primitives (Keccak-256, secp256k1, EIP-712) are
vendored below — the same constructions the endpoint's own
specimen toolkit uses. Pure Python 3 standard library; no
external dependencies.

The payer key is the BOT OWNER's own wallet key, supplied by the
owner. This client holds no key material of the service, never
touches the service's custody path, and stores nothing.

Usage as a library:

    from receipt_client import record_agreement
    result = record_agreement(
        "https://8374.stegverse.org", priv_hex,
        agreement_ref="deal-2026-11-18-001",
        authority="...", delegation="no delegation",
        evidence_refs=["<reference to the agreed terms>"])
    if result["disposition"] == "ALLOW":
        ...  # treat the deal as final; keep result["pair_id"]

Usage as a CLI:

    python3 receipt_client.py \
        --base-url https://8374.stegverse.org \
        --key-file payer.json \
        --agreement-ref deal-2026-11-18-001 \
        --authority "..." --delegation "no delegation" \
        --evidence-ref "<reference to the agreed terms>" \
        --out result.json

key-file: JSON {"priv_hex": "0x...", "address": "0x..."} — the
address is checked against the key when present.
"""
import argparse, base64, json, os, secrets, sys, time
import urllib.request, urllib.error

# ------------------------------------------------------------------
# Expected receptor constants (8374@StegVerse.ai, declared
# 2026-11-17; pricing BUILD-Q-43 / offer v07, 2026-11-18). The
# client refuses to pay anything that does not match these.
# ------------------------------------------------------------------
EXPECTED_NETWORK = "eip155:8453"                       # Base
EXPECTED_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC
EXPECTED_PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
EXPECTED_SCHEME = "exact"
AGREEMENT_SCOPE = "ME-AGREE-01"
AGREEMENT_ACTION = "record-agreement"
AGREEMENT_TIER = "full-evaluation"
GOVERNANCE_FEE_MICRO = 15000          # full-evaluation tier fee
POLICY = "ME-POLICY-01"
CLIENT_UA = "StegVerse-ReceiptClient/1.0 (8374 agent kit; BUILD-Q-49)"

# ------------------------------------------------------------------
# Keccak-256 (pure python; vector-asserted)
# ------------------------------------------------------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_R = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(state):
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _R[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))[:32]


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def eip55(addr_hex_lower: str) -> str:
    h = keccak256(addr_hex_lower.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(addr_hex_lower):
        out.append(ch.upper() if ch in "abcdef" and int(h[i], 16) >= 8 else ch)
    return "0x" + "".join(out)


# ------------------------------------------------------------------
# secp256k1 signing (pure python)
# ------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q:
        m = (3 * p[0] * p[0]) * pow(2 * p[1], -1, P) % P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (m * m - p[0] - q[0]) % P
    return (x, (m * (p[0] - x) - p[1]) % P)


def _mul(k, p):
    r = None
    while k:
        if k & 1: r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def address_from_private(priv):
    q = _mul(priv, G)
    unc = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return eip55(keccak256(unc)[-20:].hex())


def sign_digest(priv, digest_bytes):
    z = int.from_bytes(digest_bytes, "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        kg = _mul(k, G)
        r = kg[0] % N
        if r == 0:
            continue
        s = (pow(k, -1, N) * (z + r * priv)) % N
        if s == 0:
            continue
        recid = (kg[1] & 1) | (2 if kg[0] >= N else 0)
        if s > N // 2:
            s = N - s
            recid ^= 1
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])


# ------------------------------------------------------------------
# EIP-712 / EIP-3009 authorization (USDC domain on Base)
# ------------------------------------------------------------------
def _u256(n):
    return int(n).to_bytes(32, "big")


def _addr_word(a):
    return b"\x00" * 12 + bytes.fromhex(a[2:] if a.startswith("0x") else a)


_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_AUTH_TYPEHASH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,"
    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)")


def domain_separator(asset=EXPECTED_ASSET, name="USD Coin", version="2",
                     chain_id=8453):
    return keccak256(_DOMAIN_TYPEHASH + keccak256(name.encode())
                     + keccak256(version.encode()) + _u256(chain_id)
                     + _addr_word(asset))


def authorization_digest(auth, asset=EXPECTED_ASSET):
    nonce = auth["nonce"]
    nonce = nonce[2:] if nonce.startswith("0x") else nonce
    struct_hash = keccak256(
        _AUTH_TYPEHASH + _addr_word(auth["from"]) + _addr_word(auth["to"])
        + _u256(auth["value"]) + _u256(auth["validAfter"])
        + _u256(auth["validBefore"]) + bytes.fromhex(nonce))
    return keccak256(b"\x19\x01" + domain_separator(asset) + struct_hash)


def _sign_authorization(priv, payer, to, value, valid_after, valid_before):
    nonce = secrets.token_bytes(32).hex()
    auth = {"from": payer, "to": to, "value": str(value),
            "validAfter": str(valid_after), "validBefore": str(valid_before),
            "nonce": "0x" + nonce}
    sig = sign_digest(priv, authorization_digest(auth))
    return auth, "0x" + sig.hex()


def make_payment_header_v1(priv, payer, to, value, valid_after, valid_before):
    auth, sig = _sign_authorization(priv, payer, to, value,
                                    valid_after, valid_before)
    payload = {"x402Version": 1, "scheme": "exact",
               "network": EXPECTED_NETWORK,
               "payload": {"signature": sig, "authorization": auth}}
    return base64.b64encode(json.dumps(payload).encode()).decode(), auth


def make_payment_header_v2(priv, payer, to, value, valid_after, valid_before,
                           accepted, resource_url):
    """The x402 v2 envelope (BUILD-Q-48): the same EIP-3009
    authorization, wrapped as a PaymentPayload echoing the
    challenge's accepted requirements object verbatim."""
    auth, sig = _sign_authorization(priv, payer, to, value,
                                    valid_after, valid_before)
    payload = {"x402Version": 2,
               "resource": {"url": resource_url,
                            "mimeType": "application/json"},
               "accepted": accepted,
               "payload": {"signature": sig, "authorization": auth},
               "extensions": {}}
    return base64.b64encode(json.dumps(payload).encode()).decode(), auth


# ------------------------------------------------------------------
# HTTP plumbing. Egress proxy candidates are discovered from the
# environment (the pattern the endpoint's own settlement module
# uses), then direct. An HTTP error status is a response, not a
# transport failure, and is returned to the caller.
# ------------------------------------------------------------------
def _proxy_candidates():
    out = []
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        v = os.environ.get(k)
        if v and v not in out:
            out.append(v)
    out.append(None)
    return out


def _opener(proxy):
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_call_h(base, method, path, body=None, headers=None, timeout=90):
    """Returns (status, headers, body) with header keys lowercased
    (the x402 v2 signaling headers ride here: PAYMENT-REQUIRED on
    the challenge, PAYMENT-RESPONSE on the answered crossing)."""
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for proxy in _proxy_candidates():
        req = urllib.request.Request(
            base + path, data=data, method=method,
            headers={"Content-Type": "application/json",
                     "User-Agent": CLIENT_UA,
                     **(headers or {})})
        try:
            with _opener(proxy).open(req, timeout=timeout) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, hdrs, json.load(resp)
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v
                    for k, v in (e.headers.items() if e.headers else [])}
            try:
                return e.code, hdrs, json.load(e)
            except Exception:
                return e.code, hdrs, {}
        except Exception as e:  # transport failure -> next candidate
            last = e
    raise RuntimeError(f"HTTP transport failed for {method} {path}: {last}")


class Refusal(Exception):
    """The challenge or offer does not match the expected receptor:
    the client refuses to pay. Distinct from a governed NON-ALLOW
    disposition, which record_agreement returns as data."""


def load_key_file(path):
    key = json.load(open(path))
    priv = int(key["priv_hex"], 16)
    payer = address_from_private(priv)
    if key.get("address") and key["address"].lower() != payer.lower():
        raise Refusal("key file address does not match the private key")
    return priv, payer


# ------------------------------------------------------------------
# The agreement-receipt crossing — the one function a bot workflow
# calls at its agreement step.
# ------------------------------------------------------------------
def record_agreement(base_url, priv, *, agreement_ref, authority,
                     delegation, evidence_refs, exclusions=None,
                     counterparty=None, resource=None,
                     valid_seconds=3600, timeout=90):
    """Record an agreement the bot has reached as a governed
    crossing under scope ME-AGREE-01, and return the outcome.

    base_url:      the endpoint surface, e.g.
                   "https://8374.stegverse.org".
    priv:          the bot owner's payer private key (int).
    agreement_ref: the bot's own reference for the agreement; the
                   crossing's resource names it as
                   "agreement-record:<agreement_ref>" unless
                   `resource` is given explicitly.
    authority:     who authorized the bot to agree, and on what
                   basis (commit-time evidence object).
    delegation:    the delegation under which the bot acted, or an
                   explicit no-delegation statement.
    evidence_refs: non-empty list of references to the agreed
                   terms (document, thread, hash, ...).
    exclusions:    material exclusions, stated; an empty list is a
                   statement that there are none.

    Returns a dict:
      disposition                  ALLOW / DENY / FAIL_CLOSED
      pair_id                      the receipt pair (the refusal
                                   pair on NON-ALLOW)
      http_status                  the crossing response status
      total_authorized_micro_usdc  fee + settlement charge quoted
      governance_fee_micro_usdc    15000 (full-evaluation tier)
      settlement_charge_micro_usdc the quoted settlement charge
      settlement                   {status, tx_hash, failure_code}
      detail                       the six-field disposition on
                                   NON-ALLOW, else None
    Raises Refusal when the challenge does not match the expected
    receptor (nothing is paid), RuntimeError on transport failure.
    """
    payer = address_from_private(priv)
    body = {
        "counterparty": counterparty or payer,
        "action": AGREEMENT_ACTION,
        "scope_ref": AGREEMENT_SCOPE,
        "resource": resource or ("agreement-record:" + agreement_ref),
        "tier": AGREEMENT_TIER,
        "evidence": {
            "authority": authority,
            "delegation": delegation,
            "evidence_refs": list(evidence_refs),
            "exclusions": list(exclusions) if exclusions else [],
            "policy": POLICY,
            "validity_at_commit": True}}

    # 1. Unpaid -> 402 challenge (dual-stack: v1 body + v2 header).
    code, hdrs, chal = http_call_h(base_url, "POST", "/crossing",
                                   body, timeout=timeout)
    if code != 402:
        raise RuntimeError(
            f"expected 402 challenge, got HTTP {code}: "
            f"{json.dumps(chal)[:200]}")
    acc = (chal.get("accepts") or [{}])[0]
    for field, expected in (("network", EXPECTED_NETWORK),
                            ("asset", EXPECTED_ASSET),
                            ("payTo", EXPECTED_PAYTO),
                            ("scheme", EXPECTED_SCHEME)):
        if acc.get(field) != expected:
            raise Refusal(
                f"challenge mismatch on {field}: got {acc.get(field)!r}, "
                f"expected {expected!r} -- refusing to pay")
    total = int(acc["maxAmountRequired"])
    fee = int(acc.get("governance_fee_micro_usdc") or 0)
    if fee != GOVERNANCE_FEE_MICRO:
        raise Refusal(
            f"challenge governance fee {fee} != the full-evaluation "
            f"tier fee {GOVERNANCE_FEE_MICRO} -- refusing to pay")
    charge = int(acc.get("settlement_charge_micro_usdc")
                 or (total - fee))

    # 2. Sign exactly the quoted total; v2 envelope when the
    # challenge carried PAYMENT-REQUIRED, else the v1 header.
    now_ts = int(time.time())
    raw_pr = hdrs.get("payment-required")
    v2_challenge = None
    if raw_pr:
        try:
            v2_challenge = json.loads(base64.b64decode(raw_pr))
        except Exception:
            v2_challenge = None
    if v2_challenge is not None:
        if v2_challenge.get("x402Version") != 2:
            raise Refusal("PAYMENT-REQUIRED header does not declare "
                          "x402Version 2")
        vacc = (v2_challenge.get("accepts") or [{}])[0]
        for field, expected in (("network", EXPECTED_NETWORK),
                                ("asset", EXPECTED_ASSET),
                                ("payTo", EXPECTED_PAYTO),
                                ("scheme", EXPECTED_SCHEME)):
            if vacc.get(field) != expected:
                raise Refusal(f"v2 challenge mismatch on {field}: "
                              f"{vacc.get(field)!r} != {expected!r}")
        if int(vacc["amount"]) != total:
            raise Refusal(f"v2 challenge amount {vacc['amount']} "
                          f"!= v1 total {total}")
        extra = vacc.get("extra") or {}
        if extra.get("name") != "USD Coin" or extra.get("version") != "2":
            raise Refusal(f"v2 challenge EIP-712 domain mismatch: "
                          f"{extra!r}")
        hdr, auth = make_payment_header_v2(
            priv, payer, EXPECTED_PAYTO, total, now_ts - 10,
            now_ts + valid_seconds, vacc, base_url + "/crossing")
        pay_headers = {"PAYMENT-SIGNATURE": hdr}
        x402_version = 2
    else:
        hdr, auth = make_payment_header_v1(
            priv, payer, EXPECTED_PAYTO, total, now_ts - 10,
            now_ts + valid_seconds)
        pay_headers = {"X-PAYMENT": hdr}
        x402_version = 1

    # 3. Paid crossing.
    code, hdrs, resp = http_call_h(base_url, "POST", "/crossing",
                                   body, pay_headers, timeout=timeout)
    pay = resp.get("payment") or {}
    settle = resp.get("settlement") or {}
    result = {
        "disposition": resp.get("disposition"),
        "pair_id": resp.get("pair_id") or resp.get("refusal_pair_id"),
        "http_status": code,
        "scope_ref": AGREEMENT_SCOPE,
        "action": AGREEMENT_ACTION,
        "resource": body["resource"],
        "counterparty": body["counterparty"],
        "payer": payer,
        "x402_version_used": x402_version,
        "authorization_nonce": auth["nonce"],
        "total_authorized_micro_usdc":
            pay.get("total_authorized_micro_usdc", total),
        "governance_fee_micro_usdc":
            pay.get("governance_fee_micro_usdc", fee),
        "settlement_charge_micro_usdc":
            pay.get("settlement_charge_micro_usdc", charge),
        "settlement": {"status": settle.get("status"),
                       "tx_hash": settle.get("tx_hash"),
                       "failure_code": settle.get("failure_code")},
        "detail": None}
    raw_presp = hdrs.get("payment-response")
    if raw_presp:
        try:
            result["payment_response"] = json.loads(
                base64.b64decode(raw_presp))
        except Exception:
            result["payment_response"] = {"unparseable_header": True}
    if resp.get("disposition") != "ALLOW":
        result["detail"] = resp.get("detail") or {
            k: resp.get(k) for k in (
                "failure_code", "failed_predicate",
                "required_evidence_or_repair", "retry_entrypoint",
                "owning_goal", "next_attempt")}
    return result


def main():
    ap = argparse.ArgumentParser(
        description="Record an agreement as a governed 8374 "
                    "crossing (scope ME-AGREE-01).")
    ap.add_argument("--base-url", required=True,
                    help="endpoint surface, e.g. "
                         "https://8374.stegverse.org")
    ap.add_argument("--key-file", required=True,
                    help="JSON with priv_hex + address (bot owner's "
                         "payer wallet)")
    ap.add_argument("--agreement-ref", required=True,
                    help="the bot's own reference for the agreement")
    ap.add_argument("--authority", required=True,
                    help="who authorized the bot to agree, and on "
                         "what basis")
    ap.add_argument("--delegation", required=True,
                    help="the delegation the bot acted under, or an "
                         "explicit no-delegation statement")
    ap.add_argument("--evidence-ref", action="append", required=True,
                    help="reference to the agreed terms (repeatable; "
                         "at least one required)")
    ap.add_argument("--exclusion", action="append", default=[],
                    help="a material exclusion (repeatable)")
    ap.add_argument("--counterparty", default=None,
                    help="declared counterparty for the crossing "
                         "record (default: the payer address)")
    ap.add_argument("--resource", default=None,
                    help="explicit resource naming the agreement "
                         "(default: agreement-record:<agreement-ref>)")
    ap.add_argument("--out", default=None,
                    help="write the result JSON to this file")
    args = ap.parse_args()

    priv, payer = load_key_file(args.key_file)
    result = record_agreement(
        args.base_url, priv,
        agreement_ref=args.agreement_ref,
        authority=args.authority, delegation=args.delegation,
        evidence_refs=args.evidence_ref, exclusions=args.exclusion,
        counterparty=args.counterparty, resource=args.resource)
    result["client"] = "agent-kit/receipt_client.py (BUILD-Q-49)"
    print(json.dumps(result, indent=1))
    if args.out:
        json.dump(result, open(args.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
