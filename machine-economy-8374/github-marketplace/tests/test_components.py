import hashlib
import hmac
import importlib.util
import json
import io
import sys
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


app = module('app', ROOT / 'app/webhook_core.py')
sys.modules['webhook_core'] = app
receiver = module('receiver', ROOT / 'app/receiver.py')
adapters = module('adapters', ROOT / 'app/public_adapters.py')


class Fixtures:
    def __init__(self): self.reserved = set(); self.finished = []; self.calls = []
    def begin(self, d, sha):
        if d in self.reserved: return False
        self.reserved.add(d); return True
    def finish(self, d, r): self.finished.append((d, r))
    def public_origin(self, i, a): return 'https://seller.example'
    def register_public_origin(self, origin): self.calls.append(origin); return {'registered': True}
    def record_installation(self, *args): pass
    def disable_installation(self, *args): self.calls.append('disabled')
    def remove_repositories(self, *args): self.calls.append('removed')
    def record_purchase(self, *args): self.calls.append('billing')


class AppTests(unittest.TestCase):
    def setUp(self): self.f = Fixtures(); self.secret = b'fixture-secret'
    def payload(self, p, event='installation'):
        body = json.dumps(p).encode()
        return {'X-GitHub-Event': event, 'X-GitHub-Delivery': 'fixture-1',
                'X-Hub-Signature-256': 'sha256='+hmac.new(self.secret, body, hashlib.sha256).hexdigest()}, body
    def call(self, h, b):
        return app.handle(h, b, secret=self.secret, deliveries=self.f, bindings=self.f, router=self.f, github=self.f)
    def installation(self, action='created'):
        return self.payload({'action': action, 'installation': {'id': 7, 'account': {'id': 8}}})

    def test_installation_registers_only_bound_public_origin(self):
        self.assertEqual(self.call(*self.installation())['disposition'], 'PUBLIC_REGISTRATION_RECORDED')
        self.assertEqual(self.f.calls, ['https://seller.example'])

    def test_tampered_body_has_no_effect(self):
        h, b = self.installation()
        with self.assertRaises(app.NonAllow): self.call(h, b+b' ')
        self.assertFalse(self.f.reserved)

    def test_missing_signature_refused(self):
        h, b = self.installation(); del h['X-Hub-Signature-256']
        with self.assertRaises(app.NonAllow): self.call(h, b)

    def test_duplicate_delivery_refused(self):
        h, b = self.installation(); self.call(h, b)
        with self.assertRaises(app.NonAllow): self.call(h, b)
        self.assertEqual(len(self.f.calls), 1)

    def test_failed_external_effect_is_not_replayed(self):
        def fail(origin): raise TimeoutError('fixture ambiguous response')
        self.f.register_public_origin = fail
        h, b = self.installation()
        with self.assertRaises(TimeoutError): self.call(h, b)
        self.assertEqual(self.f.finished[-1][1]['disposition'], 'AMBIGUOUS_RECONCILE')
        with self.assertRaises(app.NonAllow): self.call(h, b)

    def test_cancelled_purchase_cannot_grant_entitlement(self):
        h, b = self.payload({'action': 'cancelled', 'marketplace_purchase': {'account': {'id': 8}}}, 'marketplace_purchase')
        self.assertEqual(self.call(h, b)['entitlement'], 'NOT_GRANTED')
        self.assertEqual(self.f.calls, ['billing'])

    def test_deleted_installation_disables(self):
        self.call(*self.installation('deleted')); self.assertEqual(self.f.calls, ['disabled'])

    def test_event_header_cannot_reinterpret_installation_as_purchase(self):
        h, b = self.installation(); h['X-GitHub-Event'] = 'marketplace_purchase'
        with self.assertRaises(app.NonAllow): self.call(h, b)
        self.assertFalse(self.f.reserved)

    def test_no_owner_origin_refused(self):
        self.f.public_origin = lambda *args: None
        with self.assertRaises(app.NonAllow): self.call(*self.installation())
        self.assertFalse(self.f.calls)

    def test_receipt_surface_is_neutral_and_commit_bound(self):
        check = app.receipt_check('a'*40, 'https://8374.stegverse.org/chain', 'PAIR-000001', 'b'*64)
        self.assertEqual(check['conclusion'], 'neutral')
        with self.assertRaises(app.NonAllow): app.receipt_check('', 'https://8374.stegverse.org/chain', 'PAIR-000001', 'b'*64)


class AdapterTests(unittest.TestCase):
    def test_router_uses_only_fixed_public_registration(self):
        seen = []
        original = adapters.request_json
        adapters.request_json = lambda url, **kw: seen.append((url, kw)) or {'ok': True}
        try:
            adapters.PublicRouter().register_public_origin('https://seller.example')
        finally:
            adapters.request_json = original
        self.assertEqual(seen[0][0], 'https://8374.stegverse.org/router/register')
        self.assertNotIn('token', seen[0][1])

    def test_check_rejects_repository_outside_installation(self):
        original = adapters.request_json
        adapters.request_json = lambda *a, **kw: {'repositories': []}
        try:
            with self.assertRaises(ValueError):
                adapters.GitHubInstallation(lambda i: 'fixture-token').create_installation_check(7, 'owner/repo', {})
        finally:
            adapters.request_json = original

    def test_check_requires_installation_scoped_repository_then_posts(self):
        seen = []
        original = adapters.request_json
        def request(url, **kw):
            seen.append((url, kw))
            return {'repositories': [{'full_name': 'owner/repo'}]} if 'installation/repositories' in url else {'id': 99}
        adapters.request_json = request
        try:
            result = adapters.GitHubInstallation(lambda i: 'fixture-token').create_installation_check(7, 'owner/repo', {'conclusion': 'neutral'})
        finally:
            adapters.request_json = original
        self.assertEqual(result['id'], 99)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[1][0], 'https://api.github.com/repos/owner/repo/check-runs')
        self.assertEqual(seen[1][1]['payload']['conclusion'], 'neutral')


class ReceiverTests(unittest.TestCase):
    def handler(self, body=b'{}', method='POST'):
        class Handler:
            def send_response(self, status): self.status = status
            def send_header(self, *args): pass
            def end_headers(self): pass
        h = Handler(); h.command = method
        h.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(body))}
        h.rfile = io.BytesIO(body); h.wfile = io.BytesIO()
        return h

    def test_no_bindings_fail_closed(self):
        self.assertEqual(receiver.receive(self.handler(), None), 503)
    def test_non_post_refused(self):
        self.assertEqual(receiver.receive(self.handler(method='GET'), None), 405)
    def test_oversized_body_refused_before_read(self):
        h = self.handler(); h.headers['Content-Length'] = '2000001'
        self.assertEqual(receiver.receive(h, None), 413)
        self.assertEqual(h.rfile.tell(), 0)
    def test_transfer_encoding_refused(self):
        h = self.handler(); h.headers['Transfer-Encoding'] = 'chunked'
        self.assertEqual(receiver.receive(h, None), 400)
    def test_truncated_body_refused(self):
        h = self.handler(); h.headers['Content-Length'] = '3'
        self.assertEqual(receiver.receive(h, object()), 400)
    def test_signed_delivery_replay_boundary(self):
        body = json.dumps({'zen': 'fixture', 'hook': {}}).encode()
        h = self.handler(body); f = Fixtures()
        class Context:
            deliveries = f; bindings = f; router = f; github = f
            def webhook_secret(self): return b'fixture-secret'
        h.headers.update({'X-GitHub-Event': 'ping', 'X-GitHub-Delivery': 'fixture-http',
            'X-Hub-Signature-256': 'sha256=' + hmac.new(b'fixture-secret', body, hashlib.sha256).hexdigest()})
        self.assertEqual(receiver.receive(h, Context()), 200)
        h.rfile = io.BytesIO(body); h.wfile = io.BytesIO()
        self.assertEqual(receiver.receive(h, Context()), 409)


if __name__ == '__main__': unittest.main()
