#!/usr/bin/env python3
"""Pinned-suite integrity and explicit trusted-checker execution; stdlib only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON key')
        out[key] = value
    return out


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def member_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('invalid member path')
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ('..', '.') for x in name.split('/')):
        raise ValueError('unsafe member path')
    q = root
    for part in p.parts:
        q = q / part
        if q.is_symlink():
            raise ValueError('symlink member')
    if not q.is_file() or not q.resolve().is_relative_to(root):
        raise ValueError('member absent or outside suite')
    return q


def verify(suite, expected_manifest, checker_digest='', run_checker=False, timeout=60):
    source = Path(suite).absolute()
    if source.is_symlink():
        raise ValueError('symlink suite root')
    root = source.resolve(strict=True)
    if not root.is_dir() or not hex_digest(expected_manifest):
        raise ValueError('suite directory and exact manifest SHA256 required')
    mp = member_path(root, 'PACKAGE__MANIFEST__01.json')
    raw = mp.read_bytes()
    if digest(raw) != expected_manifest:
        raise ValueError('manifest pin mismatch')
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    members = manifest.get('members')
    if not isinstance(members, list) or not members:
        raise ValueError('nonempty members list required')
    names = set()
    for entry in members:
        if not isinstance(entry, dict):
            raise ValueError('invalid manifest entry')
        name = entry.get('file')
        size = entry.get('bytes')
        sha = entry.get('sha256')
        if not isinstance(name, str) or name in names or name == mp.name:
            raise ValueError('duplicate or self-listed member')
        if type(size) is not int or size < 0 or not hex_digest(sha):
            raise ValueError('invalid member pin')
        data = member_path(root, name).read_bytes()
        if len(data) != size or digest(data) != sha:
            raise ValueError('member pin mismatch: ' + name)
        names.add(name)
    # No ignored hidden/unlisted inputs: checker imports must also be pinned.
    actual = set()
    for p in root.rglob('*'):
        if p.is_symlink():
            raise ValueError('symlink in suite')
        if p.is_file():
            actual.add(p.relative_to(root).as_posix())
    if actual != names | {mp.name}:
        raise ValueError('unlisted or missing suite files')
    needed = {'README.md', 'FUNDING__STATEMENT__01.md', 'CONFORMANCE__PROOF__01.json', 'self_check.py'}
    if not needed <= names:
        raise ValueError('conformance members missing')
    readme = (root / 'README.md').read_text()
    funding = (root / 'FUNDING__STATEMENT__01.md').read_text()
    if not manifest.get('project_id') or not manifest.get('funding'):
        raise ValueError('project/funding metadata missing')
    if not all(x in readme for x in ('ProjectID:', 'Funding:')):
        raise ValueError('README project/funding lines missing')
    if not all(x in funding for x in ('ProjectID:', 'Funding:')) or 'commercial arrangement' not in funding.lower():
        raise ValueError('funding statement incomplete')
    proof = json.loads((root / 'CONFORMANCE__PROOF__01.json').read_bytes(), object_pairs_hook=unique_object)
    required_elements = ('E1_manifest_members_verify', 'E2_self_check_passes',
                         'E2b_checker_carries_template_checks', 'E3_face_carries_projectid_funding',
                         'E4_funding_statement', 'E5_proof_in_suite')
    if any(proof.get('elements', {}).get(k, {}).get('pass') is not True for k in required_elements):
        raise ValueError('in-suite conformance assertion incomplete or false')
    result = {'schema': 'stegverse.github-suite-check/v1', 'authority_effect': 'NONE',
              'manifest_sha256': expected_manifest, 'members_verified': len(names),
              'integrity': 'PASS', 'conformance_assertions': 'PRESENT_NOT_INDEPENDENTLY_PROVEN',
              'checker': 'NOT_RUN', 'runtime_admission': 'NOT_ESTABLISHED'}
    if run_checker:
        checker = root / 'self_check.py'
        if not hex_digest(checker_digest) or digest(checker.read_bytes()) != checker_digest:
            raise ValueError('separate trusted checker pin required')
        # A pin proves identity, not safety. Only a reviewed checker may be opted in.
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL')}
        done = subprocess.run([sys.executable, '-I', '-B', str(checker)], cwd=root,
                              env=env, capture_output=True, timeout=timeout)
        if done.returncode != 0:
            raise ValueError('trusted checker failed')
        result['checker'] = 'PASS'
        result['checker_sha256'] = checker_digest
        result['checker_stdout_sha256'] = digest(done.stdout)
        # Detect checker writes, including metadata pinned by the manifest.
        verify(root, expected_manifest)
    return result


def main():
    try:
        run = os.environ.get('SUITE_RUN_CHECKER', 'false')
        if run not in ('true', 'false'):
            raise ValueError('run-checker must be true or false')
        result = verify(os.environ['SUITE_DIRECTORY'], os.environ['SUITE_MANIFEST_SHA256'],
                        os.environ.get('SUITE_CHECKER_SHA256', ''), run == 'true')
        status = 'PASS'
    except (ValueError, KeyError, OSError, TypeError, AttributeError, subprocess.TimeoutExpired) as exc:
        result = {'schema': 'stegverse.github-suite-check/v1', 'authority_effect': 'NONE',
                  'integrity': 'NON_ALLOW', 'error': str(exc), 'runtime_admission': 'NOT_ESTABLISHED'}
        status = 'NON_ALLOW'
    # Output sits outside the immutable suite; never emit caller-controlled multiline metadata.
    fd, target_name = tempfile.mkstemp(prefix='stegverse-suite-', suffix='.json',
                                       dir=os.environ.get('RUNNER_TEMP', '/tmp'))
    target = Path(target_name)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write('verdict=' + status + '\nresult-path=' + str(target) + '\n')
    print(json.dumps(result))
    return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
