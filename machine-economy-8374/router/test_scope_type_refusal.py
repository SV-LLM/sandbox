#!/usr/bin/env python3
"""Isolated scope-shape refusal regression: no funds, custody or origin calls."""
from __future__ import annotations
import http.client
from http.server import ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread
import unittest

HERE = Path(__file__).resolve().parent
BAD_SCOPES = [[], {}, None, True, False, 0, 12, 1.5]
MISSING = object()

class ScopeRefusalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='router-scope-regression-')
        cls.state = Path(cls.temp.name)
        config = {'payTo': '0x0000000000000000000000000000000000000001',
                  'settlement': {'enabled': False}, 'self_origin': 'http://127.0.0.1:1'}
        (cls.state / 'config.json').write_text(json.dumps(config))
        cls.names = {'ROUTER_DIR': str(cls.state), 'ROUTER_CONFIG_PATH': str(cls.state / 'config.json'),
                     'ROUTER_RECEIPTS_DIR': str(cls.state / 'receipts'),
                     'ROUTER_REGISTRY_PATH': str(cls.state / 'registry.json')}
        cls.previous = {key: os.environ.get(key) for key in cls.names}
        os.environ.update(cls.names)
        sys.path.insert(0, str(HERE))
        spec = importlib.util.spec_from_file_location('scope_router_under_test', HERE / 'router.py')
        cls.router = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.router)
        cls.original_connect = socket.create_connection
        def loopback_only(address, *args, **kwargs):
            if address[0] != '127.0.0.1':
                raise RuntimeError('External network prohibited in scope regression')
            return cls.original_connect(address, *args, **kwargs)
        socket.create_connection = loopback_only
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), cls.router.Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=5)
        socket.create_connection = cls.original_connect
        for key, value in cls.previous.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value
        cls.temp.cleanup()

    def request(self, scope):
        result = {'counterparty': 'isolated-scope-regression', 'seller_origin': 'http://127.0.0.1:1', 'resource': '/resource'}
        if scope is not MISSING: result['scope'] = scope
        return result

    def verify_refusal(self, run, scope, expected_code):
        before = self.router.CHAIN.totals()
        status, result = run(self.request(scope))
        after = self.router.CHAIN.totals()
        self.assertEqual(status, 422)
        self.assertEqual(result['disposition'], 'FAIL_CLOSED')
        self.assertEqual(result['detail']['failure_code'], expected_code)
        self.assertEqual(len(result['detail']), 6)
        self.assertTrue(result['pair_id'])
        self.assertEqual(result['settlement']['state'], 'NOT_SUBMITTED')
        self.assertEqual(after['receipt_pairs'] - before['receipt_pairs'], 1)
        self.assertEqual(after['chain_entries'] - before['chain_entries'], 2)

    def http(self, body):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            conn.request('POST', '/router/route', json.dumps(body), {'Content-Type': 'application/json'})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally: conn.close()

    def test_function_bad_shapes(self):
        for scope in BAD_SCOPES:
            with self.subTest(scope=scope): self.verify_refusal(self.router.do_route, scope, 'SCOPE_TYPE_INVALID')

    def test_function_existing_strings_and_default(self):
        for scope in [MISSING, 'receipt-only', 'ME-EVAL-01']:
            with self.subTest(scope=str(scope)): self.verify_refusal(self.router.do_route, scope, 'SELLER_NOT_REGISTERED')

    def test_http_bad_shapes(self):
        for scope in BAD_SCOPES:
            with self.subTest(scope=scope): self.verify_refusal(self.http, scope, 'SCOPE_TYPE_INVALID')

    def test_http_existing_strings_and_default(self):
        for scope in [MISSING, 'receipt-only', 'ME-EVAL-01']:
            with self.subTest(scope=str(scope)): self.verify_refusal(self.http, scope, 'SELLER_NOT_REGISTERED')

    def test_zz_refusal_chain_replays(self):
        result = self.router.replay(str(self.state / 'receipts'))
        self.assertEqual(result['verdict'], 'MATCH')
        self.assertEqual(self.router.CHAIN.totals()['receipt_pairs'], 22)
        self.assertEqual(self.router.CHAIN.totals()['chain_entries'], 44)

if __name__ == '__main__': unittest.main(verbosity=2)
