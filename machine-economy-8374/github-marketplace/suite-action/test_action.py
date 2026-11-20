"""Executable adapter controls; no assertion statements that disappear with -O."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('suite_action', HERE / 'run_action.py')
action = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action)


class SuiteActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.spec_body = (HERE / 'examples/instantiate.json').read_bytes()
        (cls.root / 'spec.json').write_bytes(cls.spec_body)
        result = cls.root / 'baseline'
        result.mkdir()
        cls.baseline = action.evaluate('instantiate', 'spec.json', action.digest(cls.spec_body), cls.root, result)
        cls.suite = result / 'suite'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.work = Path(self.tmp.name)
        shutil.copytree(self.suite, self.work / 'suite')
        self.result = self.work / 'result'
        self.result.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def evaluate(self):
        return action.evaluate('verify', 'suite', action.digest((self.work / 'suite' / action.MANIFEST).read_bytes()), self.work, self.result)

    def resign(self):
        p = self.work / 'suite'
        manifest = json.loads((p / action.MANIFEST).read_bytes())
        for row in manifest['members']:
            f = p / row['file']
            row.update(bytes=len(f.read_bytes()), sha256=action.digest(f.read_bytes()))
        (p / action.MANIFEST).write_text(json.dumps(manifest))

    def test_real_instantiation_prover_and_readonly_verification(self):
        before = {p.name: p.read_bytes() for p in (self.work / 'suite').iterdir()}
        out = self.evaluate()
        self.assertEqual(out['manifest_sha256'], action.digest(before[action.MANIFEST]))
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.work / 'suite').iterdir()})
        proof = json.loads(before['CONFORMANCE__PROOF__01.json'])
        self.assertEqual(proof['verdict'], 'CONFORMANT')
        self.assertTrue(all(row['pass'] for row in proof['elements'].values()))
        self.assertIn('E8_zero_placeholders_and_chained_ledger', proof['elements'])

    def test_tamper_and_missing_member_refuse_before_execution(self):
        p = self.work / 'suite' / 'README.md'
        p.write_text('changed')
        with self.assertRaisesRegex(action.Refusal, 'changed suite member'):
            self.evaluate()
        self.assertFalse((self.result / 'tool.log').exists())
        p.unlink()
        with self.assertRaises(action.Refusal):
            self.evaluate()

    def test_manifest_pin_is_required_and_binds_exact_bytes(self):
        for pin in ('', '0' * 64, 'a' * 63, 'A' * 64):
            with self.subTest(pin=pin), self.assertRaises(action.Refusal):
                action.evaluate('verify', 'suite', pin, self.work, self.result)

    def test_custom_zero_exit_checker_never_executes_even_when_resealed(self):
        marker = self.work / 'executed'
        checker = self.work / 'suite' / 'self_check.py'
        checker.write_text("# FUNDING ProjectID\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        self.resign()
        with self.assertRaisesRegex(action.Refusal, 'filed template checkers'):
            self.evaluate()
        self.assertFalse(marker.exists())

    def test_symlinks_directories_fifo_and_unlisted_files_refuse(self):
        for kind in ('symlink', 'directory', 'fifo', 'unlisted'):
            with self.subTest(kind=kind):
                p = self.work / 'suite' / 'unexpected'
                if kind == 'symlink':
                    p.symlink_to(self.work / 'suite' / 'README.md')
                elif kind == 'directory':
                    p.mkdir()
                elif kind == 'fifo':
                    os.mkfifo(p)
                else:
                    p.write_text('extra')
                with self.assertRaises((action.Refusal, OSError)):
                    self.evaluate()
                p.rmdir() if kind == 'directory' else p.unlink()

    def test_manifest_duplicate_traversal_absolute_and_boolean_pins_refuse(self):
        path = self.work / 'suite' / action.MANIFEST
        original = path.read_bytes()
        for variant in ('duplicate', '../escape', '/etc/passwd', 'boolean'):
            with self.subTest(variant=variant):
                j = json.loads(original)
                if variant == 'duplicate':
                    j['members'].append(j['members'][0].copy())
                elif variant == 'boolean':
                    j['members'][0]['bytes'] = True
                else:
                    j['members'][0]['file'] = variant
                path.write_text(json.dumps(j))
                with self.assertRaises(action.Refusal):
                    self.evaluate()
        path.write_bytes(original)

    def test_workspace_escape_and_linked_parent_refuse(self):
        (self.work / 'link').symlink_to(self.work / 'suite', target_is_directory=True)
        for name in ('../outside', '/etc', 'link', 'link/README.md'):
            with self.subTest(name=name), self.assertRaises(action.Refusal):
                action.workspace_path(self.work, name)

    def test_duplicate_json_keys_refuse(self):
        with self.assertRaisesRegex(action.Refusal, 'keys must be unique'):
            action.parse(b'{"members": [], "members": []}')

    def test_resealed_placeholders_and_invalid_ledger_are_actual_nonconformance(self):
        for name, body in [('REFERENCES__01.md', 'TODO: unfilled'), ('LEDGER__01.json', '{}')]:
            with self.subTest(name=name):
                self.result = self.work / ('result-' + name)
                self.result.mkdir()
                p = self.work / 'suite' / name
                original = p.read_bytes()
                p.write_text(body)
                self.resign()
                with self.assertRaisesRegex(action.Refusal, 'prover returned non-conformance'):
                    self.evaluate()
                p.write_bytes(original)
                self.resign()

    def test_spec_unknown_command_paths_and_nonstring_values_refuse(self):
        for change in ({'out': '/tmp/not-authorized'}, {'command': 'touch marker'}, {'purpose': []}):
            data = json.loads(self.spec_body)
            data.update(change)
            source = self.work / 'bad.json'
            source.write_text(json.dumps(data))
            with self.subTest(change=change), self.assertRaisesRegex(action.Refusal, 'documented string fields'):
                action.evaluate('instantiate', source.name, action.digest(source.read_bytes()), self.work, self.result)

    def test_spec_shell_metacharacters_are_literal_prose(self):
        marker = self.work / 'shell-ran'
        data = json.loads(self.spec_body)
        data['purpose'] = 'Literal $(touch ' + str(marker) + '); `touch ' + str(marker) + '`'
        source = self.work / 'literal.json'
        source.write_text(json.dumps(data))
        result = self.work / 'literal-result'
        result.mkdir()
        action.evaluate('instantiate', source.name, action.digest(source.read_bytes()), self.work, result)
        self.assertFalse(marker.exists())
        self.assertIn(data['purpose'], (result / 'suite' / 'SUITE__CHARTER__01.md').read_text())

    def test_cli_failure_has_six_fields_and_controlled_outputs(self):
        output = self.work / 'output.txt'
        env = os.environ.copy()
        env.update(GITHUB_WORKSPACE=str(self.work), RUNNER_TEMP=str(self.work), GITHUB_OUTPUT=str(output),
                   SUITE_ACTION_MODE='verify', SUITE_ACTION_SOURCE='suite', SUITE_ACTION_MANIFEST_SHA256='0' * 64)
        r = subprocess.run([sys.executable, '-I', str(HERE / 'run_action.py')], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        path = Path(json.loads(r.stdout)['report_path'])
        report = json.loads(path.read_bytes())
        self.assertEqual(report['failure_code'], 'SHA256_MISMATCH')
        for key in ('failure_code', 'failed_predicate', 'required_evidence_or_repair', 'retry_entrypoint', 'owning_existing_goal', 'next_attempt'):
            self.assertTrue(report[key])
        self.assertEqual(report['authority_effect'], 'NONE_SOURCE_VALIDATION_ONLY')
        self.assertIn('verdict=FAIL_CLOSED\n', output.read_text())

    def test_unlisted_shadow_module_never_imports(self):
        marker = self.work / 'shadow-ran'
        path = self.work / 'suite' / 'json.py'
        path.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        jpath = self.work / 'suite' / action.MANIFEST
        j = json.loads(jpath.read_bytes())
        j['members'].append({'file': 'json.py', 'bytes': path.stat().st_size, 'sha256': action.digest(path.read_bytes())})
        jpath.write_text(json.dumps(j))
        # A manifest-bound arbitrary data file is allowed, but cannot shadow Python's stdlib.
        out = self.evaluate()
        self.assertTrue(out['manifest_sha256'])
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
