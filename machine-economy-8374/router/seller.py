#!/usr/bin/env python3
"""Specimen third-party x402 seller (ROUTER-V1 battery support).

A tiny independent seller service: one paid resource
(POST /resource), its own throwaway payTo, standard x402 v1
challenge/verify behavior. It is NOT part of the router — it is
the third party the router routes to, standing in for any
self-serve registrant.

Env: SELLER_PORT (default 8898), SELLER_PAYTO (required),
SELLER_PRICE (micro-USDC, default 3000), SELLER_MODE
(normal | drop — in drop mode a PAID request is read in full and
the connection is then closed with no response: the mid-route
ambiguity specimen).

The seller verifies presented authorizations cryptographically
(x402kit), tracks its own single-use nonce registry in memory,
and counts requests for battery assertions (GET /stats). It
settles nothing itself in these batteries: in relay mode the
authorization it received remains submittable by it; in settle
mode the router's relayer submits it.
"""
import json, os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import x402kit

PORT = int(os.environ.get("SELLER_PORT", "8898"))
PAYTO = os.environ.get("SELLER_PAYTO", "")
PRICE = int(os.environ.get("SELLER_PRICE", "3000"))
MODE = os.environ.get("SELLER_MODE", "normal")
RESOURCE_PATH = "/resource"

STATS = {"requests": 0, "paid_requests": 0, "challenges": 0,
         "served": 0}
NONCES = set()
LOCK = threading.Lock()


def challenge(origin):
    return {"x402Version": 1,
            "error": "payment required",
            "accepts": [{"scheme": x402kit.SCHEME,
                         "network": x402kit.NETWORK,
                         "asset": x402kit.USDC_BASE,
                         "payTo": PAYTO,
                         "maxAmountRequired": str(PRICE),
                         "resource": origin + RESOURCE_PATH,
                         "mimeType": "application/json",
                         "description": "specimen paid resource "
                                        "(ROUTER-V1 battery seller)"}]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _origin(self):
        return f"http://127.0.0.1:{PORT}"

    def do_GET(self):
        if self.path == "/.well-known/x402":
            self._send(200, {"version": 1,
                             "resources": [self._origin()
                                           + RESOURCE_PATH]})
        elif self.path == "/openapi.json":
            self._send(200, {
                "openapi": "3.0.0",
                "info": {"title": "specimen seller", "version": "1"},
                "paths": {RESOURCE_PATH: {"post": {
                    "x-payment-info": {
                        "price_micro_usdc": PRICE,
                        "asset": x402kit.USDC_BASE,
                        "network": x402kit.NETWORK,
                        "payTo": PAYTO},
                    "responses": {"200": {"description": "the resource"},
                                  "402": {"description":
                                          "payment required"}}}}}})
        elif self.path == "/stats":
            with LOCK:
                self._send(200, dict(STATS))
        elif self.path == "/health":
            self._send(200, {"status": "ok", "service": "specimen-seller",
                             "payTo": PAYTO, "price_micro_usdc": PRICE,
                             "mode": MODE})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != RESOURCE_PATH:
            self._send(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        with LOCK:
            STATS["requests"] += 1
        hdr = self.headers.get("X-PAYMENT")
        if not hdr:
            with LOCK:
                STATS["challenges"] += 1
            self._send(402, challenge(self._origin()))
            return
        with LOCK:
            STATS["paid_requests"] += 1
        if MODE == "drop":
            # The payment was received in full; the connection now
            # dies with no response — the buyer's outcome is
            # genuinely unknowable from the response channel.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.connection.close()
            self.close_connection = True
            return
        payload = x402kit.decode_payment_header(hdr)
        if payload is None:
            self._send(400, {"error": "PAYMENT_PAYLOAD_MALFORMED"})
            return
        try:
            ev = x402kit.verify_authorization(
                payload, PAYTO, PRICE, int(time.time()))
        except x402kit.VerifyFail as e:
            self._send(403, {"error": e.code,
                             "failed_predicate": e.predicate})
            return
        with LOCK:
            if ev["nonce"] in NONCES:
                self._send(403, {"error": "PAYMENT_NONCE_REUSED"})
                return
            NONCES.add(ev["nonce"])
            STATS["served"] += 1
        self._send(200, {"resource": "specimen-resource",
                         "data": "the specimen seller's paid payload",
                         "paid": True, "amount_micro_usdc": PRICE,
                         "payer": ev["from"]})


if __name__ == "__main__":
    if not PAYTO:
        raise SystemExit("SELLER_PAYTO is required")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"specimen seller on 127.0.0.1:{PORT} payTo={PAYTO} "
          f"price={PRICE} mode={MODE}", flush=True)
    srv.serve_forever()
