"""Q55 immutable-source readback controls; stdlib only, no imported product code."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('q55', ROOT / 'scripts/q55_source_census.py')
q55 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q55)


class CensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.repo = Path(cls.temp.name)
        def git(*args):
            return subprocess.check_output(['git', '-C', str(cls.repo), *args], stderr=subprocess.PIPE)
        git('init', '-q')
        git('config', 'user.name', 'Q55 local test fixture')
        git('config', 'user.email', 'q55-test@example.invalid')
        for name, data in [('one.py', b'exact bytes\n'), ('two.py', b'exact bytes\n'), ('different.py', b'other\n')]:
            (cls.repo / name).write_bytes(data)
        (cls.repo / 'source-link').symlink_to('/outside/not-read')
        cls.marker = cls.repo / 'MUST_NOT_EXECUTE'
        (cls.repo / 'never_import.py').write_text('from pathlib import Path\nPath(' + repr(str(cls.marker)) + ').touch()\n')
        git('add', '.')
        git('commit', '-qm', 'synthetic source fixture only')
        cls.revision = git('rev-parse', 'HEAD').decode().strip()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def row(self, path='machine-economy-endpoint/one.py', data=b'exact bytes\n'):
        return {'path': path, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def census(self, rows=None):
        rows = rows if rows is not None else [self.row()]
        return {'census': 'WORKSPACE__SOURCE__CENSUS__Q55__01', 'trees': sorted(q55.TREES),
                'allowlist_extensions': ['.py', '.json', '.md'], 'entry_count': len(rows), 'excluded_count': 0, 'entries': rows}

    def report(self, doc=None):
        data = json.dumps(doc or self.census()).encode()
        return q55.compare(data, hashlib.sha256(data).hexdigest(), self.repo, self.revision)

    def reject(self, doc):
        data = json.dumps(doc).encode()
        with self.assertRaises((ValueError, TypeError)):
            q55.parse_census(data, hashlib.sha256(data).hexdigest())

    def test_exact_matches_include_every_native_path_without_guessing_targets(self):
        report = self.report()
        self.assertEqual(report['byte_coverage'], {'EXACT_NATIVE_BYTES_AVAILABLE': 1})
        self.assertEqual({x['path'] for x in report['rows'][0]['native_matches']}, {'one.py', 'two.py'})
        self.assertFalse(report['source_target_mapping_verified'])
        self.assertFalse(report['full_migration_verified'])

    def test_missing_payload_requests_group_aliases_without_duplicate_bytes(self):
        report = self.report(self.census([self.row('chain-export/a.py', b'missing'), self.row('lane-callsite-8374/a.py', b'missing')]))
        self.assertEqual(report['byte_coverage'], {'SOURCE_PAYLOAD_REQUIRED': 2})
        self.assertEqual(report['unique_missing_payloads'], 1)
        self.assertEqual(report['missing_payload_bytes'], 7)
        self.assertEqual(len(report['payload_requests'][0]['workspace_paths']), 2)

    def test_dirty_worktree_does_not_replace_immutable_commit_bytes(self):
        path = self.repo / 'one.py'
        old = path.read_bytes()
        path.write_bytes(b'not the commit')
        try:
            self.assertIn('one.py', [x['path'] for x in self.report()['rows'][0]['native_matches']])
        finally:
            path.write_bytes(old)

    def test_git_symlink_body_is_not_reusable_source(self):
        report = self.report(self.census([self.row(data=b'/outside/not-read')]))
        self.assertEqual(report['byte_coverage'], {'SOURCE_PAYLOAD_REQUIRED': 1})
        self.assertEqual(report['native_nonregular_modes_excluded'], {'120000': 1})

    def test_pins_and_denominator_are_mandatory(self):
        data = json.dumps(self.census()).encode()
        for sha in ('', '0' * 64, 'A' * 64):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                q55.parse_census(data, sha)
        for value in (0, True, 2):
            doc = self.census(); doc['entry_count'] = value
            self.reject(doc)
        self.reject(self.census([]))

    def test_duplicate_json_keys_and_source_paths_refuse(self):
        data = b'{"census":1,"census":2}'
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            q55.parse_census(data, hashlib.sha256(data).hexdigest())
        self.reject(self.census([self.row(), self.row()]))

    def test_traversal_absolute_wrong_root_and_control_paths_refuse(self):
        for path in ('/etc/a.py', '../a.py', 'machine-economy-endpoint/../a.py',
                     'machine-economy-endpoint//a.py', 'machine-economy-endpoint\\a.py',
                     'other/a.py', 'chain-export/a\n.py'):
            with self.subTest(path=path):
                self.reject(self.census([self.row(path)]))

    def test_bad_hashes_and_boolean_or_negative_lengths_refuse(self):
        for update in ({'size': True}, {'size': -1}, {'size': 1.2}, {'sha256': 'a' * 63}, {'sha256': []}):
            row = self.row(); row.update(update)
            self.reject(self.census([row]))

    def test_payload_or_authority_fields_never_enter_the_source_census(self):
        for key in ('content', 'payload', 'authority_effect'):
            row = self.row(); row[key] = 'not an input to this tool'
            self.reject(self.census([row]))

    def test_custody_and_unlisted_extension_paths_refuse(self):
        for name in ('chain-export/private_key.json', 'chain-export/keys/a.py', 'chain-export/a.bin'):
            self.reject(self.census([self.row(name)]))

    def test_only_immutable_commit_arguments_are_accepted(self):
        for revision in ('main', '--all', self.revision[:8], '0' * 40):
            with self.subTest(revision=revision), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                q55.native_index(self.repo, revision)

    def test_source_python_files_are_read_as_bytes_and_never_imported(self):
        body = (self.repo / 'never_import.py').read_bytes()
        report = self.report(self.census([self.row('chain-export/never_import.py', body)]))
        self.assertEqual(report['byte_coverage'], {'EXACT_NATIVE_BYTES_AVAILABLE': 1})
        self.assertFalse(self.marker.exists())

    def test_cli_preserves_incomplete_status_and_structured_input_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'census.json'; output = root / 'report.json'
            body = json.dumps(self.census([self.row(data=b'not in the repository')])).encode(); source.write_bytes(body)
            cmd = [sys.executable, '-I', str(ROOT / 'scripts/q55_source_census.py'), '--census', str(source),
                   '--census-sha256', hashlib.sha256(body).hexdigest(), '--repo', str(self.repo),
                   '--revision', self.revision, '--output', str(output)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            report = json.loads(output.read_bytes())
            self.assertEqual(report['unique_missing_payloads'], 1)
            self.assertFalse(report['full_migration_verified'])
            source.write_text('{}')
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            refusal = json.loads(result.stdout)
            for key in ('failure_code', 'failed_predicate', 'required_evidence_or_repair', 'retry_entrypoint', 'owning_existing_goal', 'next_attempt'):
                self.assertTrue(refusal[key])


if __name__ == '__main__':
    unittest.main()
