#!/usr/bin/env python3
"""x402 specimen payer toolkit (BUILD-Q-18/19 demonstration support).

A pure-python EIP-3009 payer: generates a THROWAWAY keypair, builds
transferWithAuthorization payloads under the USDC EIP-712 domain on
Base, signs them (secp256k1, RFC-6979-free random-k with low-s
normalization), and emits the base64 X-PAYMENT header value.

SPECIMEN ONLY: keys produced here are unfunded demonstration payers.
They are never SKAP material, never stored by the endpoint, and prove
protocol validity only — an authorization from an unfunded payer
would settle on submission only against a funded payer.
"""
import base64, json, secrets, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak_pure import keccak256, eip55

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CHAIN_ID = 8453

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
    q = _mul(priv, G)
    unc = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return priv, eip55(keccak256(unc)[-20:].hex())

def _u256(n):
    return int(n).to_bytes(32, "big")

def _addr_word(a):
    return b"\x00" * 12 + bytes.fromhex(a[2:] if a.startswith("0x") else a)

_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_AUTH_TYPEHASH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,"
    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)")

def domain_separator(asset=USDC_BASE, name="USD Coin", version="2",
                     chain_id=CHAIN_ID):
    return keccak256(_DOMAIN_TYPEHASH + keccak256(name.encode())
                     + keccak256(version.encode()) + _u256(chain_id)
                     + _addr_word(asset))

def authorization_digest(auth, asset=USDC_BASE):
    nonce = auth["nonce"]
    nonce = nonce[2:] if nonce.startswith("0x") else nonce
    struct_hash = keccak256(
        _AUTH_TYPEHASH + _addr_word(auth["from"]) + _addr_word(auth["to"])
        + _u256(auth["value"]) + _u256(auth["validAfter"])
        + _u256(auth["validBefore"]) + bytes.fromhex(nonce))
    return keccak256(b"\x19\x01" + domain_separator(asset) + struct_hash)

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

def make_payment_header(priv, payer, to, value, valid_after, valid_before,
                        nonce_bytes=None, network="eip155:8453",
                        asset=None):
    """Returns (header_b64, authorization_dict, digest_hex)."""
    nonce = (nonce_bytes or secrets.token_bytes(32)).hex()
    auth = {"from": payer, "to": to, "value": str(value),
            "validAfter": str(valid_after), "validBefore": str(valid_before),
            "nonce": "0x" + nonce}
    digest = authorization_digest(auth)
    sig = sign_digest(priv, digest)
    payload = {"x402Version": 1, "scheme": "exact", "network": network,
               "payload": {"signature": "0x" + sig.hex(),
                           "authorization": auth}}
    if asset is not None:
        payload["asset"] = asset
    return base64.b64encode(json.dumps(payload).encode()).decode(), auth, \
        "0x" + digest.hex()
