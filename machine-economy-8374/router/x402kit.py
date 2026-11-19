#!/usr/bin/env python3
"""x402 exact-scheme toolkit for the 8374 router build (ROUTER-V1).

Vendored constructions, matching the production endpoint's own
(BUILD-Q-18 verification core; x402_specimen.py payer toolkit):
EIP-712 / EIP-3009 transferWithAuthorization under the USDC domain
on Base (name "USD Coin", version "2", chainId 8453), secp256k1
signing and recovery, payment-header construction (buyer side) and
payment-payload verification (router / seller side).

Pure Python 3 standard library. This module holds no keys and
stores nothing; key material is passed in by callers (specimen /
throwaway keys in the batteries, bot-owner keys in real use).
"""
import base64, json, secrets
from keccak_pure import keccak256, eip55

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
NETWORK = "eip155:8453"
SCHEME = "exact"
CHAIN_ID = 8453
ASSET_NAME = "USD Coin"
ASSET_VERSION = "2"


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


def new_keypair():
    priv = secrets.randbelow(N - 1) + 1
    return priv, address_from_private(priv)


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
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") \
            + bytes([27 + recid])


def _ec_recover_address(digest_bytes, r, s, recid):
    """Recover the signer address from (r, s, recid) over a digest;
    None when recovery is impossible (production construction)."""
    if not (1 <= r < N and 1 <= s < N and recid in (0, 1)):
        return None
    x = r + (recid >> 1) * N
    if x >= P:
        return None
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    y = beta if (beta & 1) == (recid & 1) else P - beta
    if (y * y) % P != alpha:
        return None
    R = (x, y)
    # Q = r^-1 (sR - zG)
    z = int.from_bytes(digest_bytes, "big") % N
    rinv = pow(r, -1, N)
    sR = _mul(s, R)
    zG = _mul(z, G)
    neg_zG = (zG[0], (-zG[1]) % P) if zG is not None else None
    Q = _mul(rinv, _add(sR, neg_zG))
    if Q is None:
        return None
    unc = Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
    return eip55(keccak256(unc)[-20:].hex())


def _u256(n):
    return int(n).to_bytes(32, "big")


def _addr_word(a):
    return b"\x00" * 12 + bytes.fromhex(a[2:] if a.startswith("0x") else a)


_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_AUTH_TYPEHASH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,"
    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)")


def domain_separator(asset=USDC_BASE):
    return keccak256(_DOMAIN_TYPEHASH + keccak256(ASSET_NAME.encode())
                     + keccak256(ASSET_VERSION.encode()) + _u256(CHAIN_ID)
                     + _addr_word(asset))


def authorization_digest(auth, asset=USDC_BASE):
    nonce = auth["nonce"]
    nonce = nonce[2:] if nonce.startswith("0x") else nonce
    struct_hash = keccak256(
        _AUTH_TYPEHASH + _addr_word(auth["from"]) + _addr_word(auth["to"])
        + _u256(auth["value"]) + _u256(auth["validAfter"])
        + _u256(auth["validBefore"]) + bytes.fromhex(nonce))
    return keccak256(b"\x19\x01" + domain_separator(asset) + struct_hash)


def norm_nonce(nonce):
    if not isinstance(nonce, str):
        return None
    n = nonce[2:] if nonce.startswith("0x") else nonce
    if len(n) != 64:
        return None
    try:
        bytes.fromhex(n)
    except ValueError:
        return None
    return "0x" + n.lower()


def make_payment_header(priv, payer, to, value, valid_after, valid_before,
                        nonce_bytes=None, network=NETWORK, asset=None):
    """Buyer side (x402_specimen.make_payment_header, same form):
    returns (header_b64, authorization_dict, digest_hex)."""
    nonce = (nonce_bytes or secrets.token_bytes(32)).hex()
    auth = {"from": payer, "to": to, "value": str(value),
            "validAfter": str(valid_after), "validBefore": str(valid_before),
            "nonce": "0x" + nonce}
    digest = authorization_digest(auth)
    sig = sign_digest(priv, digest)
    payload = {"x402Version": 1, "scheme": SCHEME, "network": network,
               "payload": {"signature": "0x" + sig.hex(),
                           "authorization": auth}}
    if asset is not None:
        payload["asset"] = asset
    return base64.b64encode(json.dumps(payload).encode()).decode(), auth, \
        "0x" + digest.hex()


def decode_payment_header(header_b64):
    """Returns the decoded payload dict, or None when the presented
    header is not a base64 JSON object at all (garbled)."""
    if not isinstance(header_b64, str) or not header_b64:
        return None
    try:
        raw = base64.b64decode(header_b64, validate=True)
        obj = json.loads(raw)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


class VerifyFail(Exception):
    def __init__(self, code, predicate, repair):
        super().__init__(code)
        self.code = code
        self.predicate = predicate
        self.repair = repair


def verify_authorization(payload, expected_payto, expected_value,
                         now_ts, asset=USDC_BASE):
    """The shared exact-scheme verification core (production
    _verify_payment_dict, BUILD-Q-18), parameterized on the
    expected payee and value: requirements match, authorization
    shape, payee, exact value, validity window, signature recovery.
    The single-use nonce predicate is the CALLER's (it owns the
    nonce registry); the normalized nonce is returned in the
    evidence so the caller can check it. Raises VerifyFail with
    the production failure codes. Returns the payment evidence
    dict (production-shaped: carries signature / nonce / from /
    to / value_micro_usdc / valid_after / valid_before / asset /
    payTo — everything settlement.build_transfer_calldata needs).
    """
    def fail(code, predicate, repair):
        raise VerifyFail(code, predicate, repair)
    if not isinstance(payload, dict):
        fail("PAYMENT_PAYLOAD_MALFORMED",
             "the payment payload is a JSON object",
             "present the base64-encoded x402 payment payload object")
    if payload.get("scheme") != SCHEME or payload.get("network") != NETWORK:
        fail("PAYMENT_REQUIREMENTS_MISMATCH",
             "the payment payload matches the declared requirements (scheme exact, network eip155:8453)",
             "pay under the requirements stated in the 402 response: scheme 'exact', network 'eip155:8453', asset USDC on Base")
    if payload.get("asset") is not None \
            and str(payload["asset"]).lower() != asset.lower():
        fail("PAYMENT_REQUIREMENTS_MISMATCH",
             "the payment asset is the declared asset (USDC on Base)",
             "pay in the declared asset: " + asset)
    pl = payload.get("payload")
    if not isinstance(pl, dict) or not isinstance(pl.get("authorization"), dict) \
            or not isinstance(pl.get("signature"), str):
        fail("PAYMENT_PAYLOAD_MALFORMED",
             "the payment payload carries payload.signature and payload.authorization",
             "present payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}")
    auth = pl["authorization"]
    for k in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if k not in auth:
            fail("PAYMENT_PAYLOAD_MALFORMED",
                 "the authorization carries from, to, value, validAfter, validBefore, nonce",
                 f"present authorization.{k} in the EIP-3009 authorization")
    if not (isinstance(auth["from"], str) and isinstance(auth["to"], str)
            and auth["from"].startswith("0x") and auth["to"].startswith("0x")
            and len(auth["from"]) == 42 and len(auth["to"]) == 42):
        fail("PAYMENT_PAYLOAD_MALFORMED",
             "authorization.from and authorization.to are 20-byte hex addresses",
             "present from/to as 0x-prefixed 20-byte addresses")
    if auth["to"].lower() != expected_payto.lower():
        fail("PAYMENT_PAYEE_MISMATCH",
             "the authorization pays the declared receptor (to == payTo)",
             "authorize the transfer to payTo " + expected_payto)
    try:
        value = int(auth["value"]); valid_after = int(auth["validAfter"])
        valid_before = int(auth["validBefore"])
    except (TypeError, ValueError):
        fail("PAYMENT_PAYLOAD_MALFORMED",
             "authorization value, validAfter, validBefore are integers (value in the asset's smallest unit)",
             "present value/validAfter/validBefore as integers")
    if value != expected_value:
        fail("PAYMENT_VALUE_INSUFFICIENT" if value < expected_value
             else "PAYMENT_VALUE_MISMATCH",
             f"the authorized value equals exactly the expected total ({expected_value} micro-USDC)",
             f"authorize exactly {expected_value} micro-USDC, as stated in the 402 challenge")
    if not (valid_after <= now_ts < valid_before):
        fail("PAYMENT_AUTHORIZATION_NOT_IN_WINDOW",
             "the authorization is inside its validity window (validAfter <= now < validBefore)",
             "sign a fresh authorization whose window covers the crossing time")
    nonce = norm_nonce(auth["nonce"])
    if nonce is None:
        fail("PAYMENT_PAYLOAD_MALFORMED",
             "the authorization nonce is a 32-byte hex value",
             "present nonce as 32 bytes of hex (0x-prefixed or bare)")
    sig_hex = pl["signature"]
    sig_hex = sig_hex[2:] if sig_hex.startswith("0x") else sig_hex
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        sig = b""
    if len(sig) != 65:
        fail("PAYMENT_SIGNATURE_INVALID",
             "the EIP-3009 signature is a 65-byte secp256k1 signature that recovers to authorization.from",
             "sign the EIP-712 transferWithAuthorization digest under the USDC domain (name 'USD Coin', version '2', chainId 8453, verifyingContract the asset) with the payer key")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    recid = v - 27 if v in (27, 28) else v
    if recid not in (0, 1):
        fail("PAYMENT_SIGNATURE_INVALID",
             "the EIP-3009 signature is a 65-byte secp256k1 signature that recovers to authorization.from",
             "present v as 27/28 (or 0/1) with r,s over the EIP-712 authorization digest")
    digest_bytes = authorization_digest({**auth, "nonce": nonce,
                                         "value": value,
                                         "validAfter": valid_after,
                                         "validBefore": valid_before},
                                        asset)
    recovered = _ec_recover_address(digest_bytes, r, s, recid)
    if recovered is None or recovered.lower() != auth["from"].lower():
        fail("PAYMENT_SIGNATURE_INVALID",
             "the EIP-3009 signature recovers to authorization.from over the authorization digest",
             "sign the EIP-712 transferWithAuthorization digest under the USDC domain (name 'USD Coin', version '2', chainId 8453, verifyingContract the asset) with the payer key")
    return {"scheme": SCHEME, "network": NETWORK, "asset": asset,
            "payTo": expected_payto,
            "from": auth["from"], "to": auth["to"],
            "value": str(value), "value_micro_usdc": value,
            "valid_after": valid_after, "valid_before": valid_before,
            "nonce": nonce,
            "authorization_digest": "0x" + digest_bytes.hex(),
            "signature_verified": True,
            "signature": "0x" + sig_hex}
