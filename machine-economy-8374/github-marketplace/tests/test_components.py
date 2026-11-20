import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


suite = module('suite', ROOT / 'action/verify_suite.py')
app = module('app', ROOT / 'app/webhook_core.py')
adapters = module('adapters', ROOT / 'app/public_adapters.py')


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        elems = {k: {'pass': True} for k in ('E1_manifest_members_verify', 'E2_self_check_passes',
                 'E2b_checker_carries_template_checks', 'E3_face_carries_projectid_funding',
                 'E4_funding_statement', 'E5_proof_in_suite')}
        self.files = {'README.md': 'ProjectID: test\nFunding: fixture\n',
                      'FUNDING__STATEMENT__01.md': 'ProjectID: test\nFunding: fixture\ncommercial arrangement: none\n',
                      'CONFORMANCE__PROOF__01.json': json.dumps({'elements': elems}),
                      'self_check.py': 'print("fixture check")\n'}
        for n, b in self.files.items():
            (self.root/n).write_text(b)
        self.repin()

    def tearDown(self):
        self.temp.cleanup()

    def repin(self):
        members = [{'file': n, 'bytes': len((self.root/n).read_bytes()),
                    'sha256': suite.digest((self.root/n).read_bytes())} for n in self.files]
        self.manifest = {'project_id': 'TEST', 'funding': 'fixture', 'members': members}
        self.write_manifest()

    def write_manifest(self):
        raw = json.dumps(self.manifest).encode()
        (self.root/'PACKAGE__MANIFEST__01.json').write_bytes(raw)
        self.pin = suite.digest(raw)

    def test_pinned_integrity_and_reviewed_execution(self):
        result = suite.verify(self.root, self.pin, suite.digest((self.root/'self_check.py').read_bytes()), True)
        self.assertEqual(result['checker'], 'PASS')
        self.assertEqual(result['runtime_admission'], 'NOT_ESTABLISHED')

    def test_corrupt_member_refused(self):
        (self.root/'README.md').write_text('changed')
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)

    def test_wrong_manifest_pin_refused(self):
        with self.assertRaises(ValueError): suite.verify(self.root, '0'*64)

    def test_unlisted_hidden_file_refused(self):
        (self.root/'.unexpected').write_text('untracked')
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)

    def test_parent_escape_refused(self):
        self.manifest['members'][0]['file'] = '../secret'
        self.write_manifest()
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)

    def test_symlink_refused(self):
        (self.root/'README.md').unlink()
        (self.root/'README.md').symlink_to(self.root/'self_check.py')
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)

    def test_duplicate_member_refused(self):
        self.manifest['members'].append(self.manifest['members'][0])
        self.write_manifest()
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)

    def test_checker_requires_separate_trust_pin(self):
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin, '', True)

    def test_mutating_checker_refused(self):
        (self.root/'self_check.py').write_text('from pathlib import Path\nPath("README.md").write_text("tampered")\n')
        self.repin()
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin, suite.digest((self.root/'self_check.py').read_bytes()), True)

    def test_false_conformance_assertion_refused(self):
        p = json.loads((self.root/'CONFORMANCE__PROOF__01.json').read_text())
        p['elements']['E4_funding_statement']['pass'] = False
        (self.root/'CONFORMANCE__PROOF__01.json').write_text(json.dumps(p))
        self.repin()
        with self.assertRaises(ValueError): suite.verify(self.root, self.pin)


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


if __name__ == '__main__': unittest.main()
