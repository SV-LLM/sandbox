#!/usr/bin/env python3
"""Offline transport adapter for the unchanged, explicitly pinned suite tools."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'vendor/template-gen02'
TEMPLATE_SHA = 'b733339c719c6dd7c884a0a3c5f24b7fa347a27a9a72049dfa6d90aa04276ffa'
GEN01_CHECKER_SHA = '9f9207293b11f928fed46d5fe9a1a5ef41074825a90825588b97a1298bb32f7e'
GEN02_CHECKER_SHA = '3bdf533c44cd17f28db8ac7522f130d05bb5b1c5f2aae9d12fa91d6191f934b1'
MANIFEST = 'PACKAGE__MANIFEST__01.json'
HEX = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_. -]{0,160}')
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
REQUIRED = ('name', 'generation', 'project-id', 'funding-line', 'funder',
            'arrangement', 'source', 'purpose', 'levels', 'member-title',
            'body', 'pointers', 'accounts-for-errors')
OPTIONAL = ('suite-project-id', 'subject', 'meter-instruments', 'error-classes',
            'reading-date', 'reading-counts-json', 'compensation-line', 'prior-readings-rows')


class Refusal(ValueError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def require(ok, code, detail):
    if not ok:
        raise Refusal(code, detail)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'DUPLICATE_JSON_KEY', 'JSON keys must be unique')
        out[key] = value
    return out


def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def pinned(data, expected):
    require(bool(HEX.fullmatch(expected)), 'MISSING_SHA256', 'Supply a lowercase SHA-256 trust anchor')
    require(digest(data) == expected, 'SHA256_MISMATCH', 'Bytes differ from the supplied trust anchor')


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'NOT_REGULAR_FILE', 'Only regular files are accepted')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_FILE + 1)
        require(len(data) <= MAX_FILE, 'INPUT_TOO_LARGE', 'File exceeds the bounded input size')
        return data
    finally:
        os.close(fd)


def workspace_path(workspace, relative):
    p = Path(relative)
    require(bool(relative) and not p.is_absolute() and '..' not in p.parts,
            'WORKSPACE_PATH_INVALID', 'Input must be a relative workspace path without traversal')
    q = workspace
    for part in p.parts:
        q = q / part
        require(not q.is_symlink(), 'SYMLINK_REFUSED', 'Input paths must not contain symlinks')
    require(q.resolve().is_relative_to(workspace), 'WORKSPACE_ESCAPE', 'Input must remain in the workspace')
    return q


def template_custody():
    data = read_regular(TEMPLATE / 'TEMPLATE__MANIFEST__02.json')
    pinned(data, TEMPLATE_SHA)
    manifest = parse(data)
    expected = {'TEMPLATE__MANIFEST__02.json'}
    for row in manifest['components']:
        name = row['file']
        require(isinstance(name, str) and bool(NAME.fullmatch(name)) and name not in expected,
                'TEMPLATE_PATH_INVALID', 'Template member names must be unique and flat')
        expected.add(name)
        body = read_regular(TEMPLATE / name)
        require(len(body) == row['bytes'] and digest(body) == row['sha256'],
                'TEMPLATE_CUSTODY_MISMATCH', 'Vendored template component changed: ' + name)
    require({p.name for p in TEMPLATE.iterdir()} == expected,
            'TEMPLATE_EXTRA_FILES', 'The complete pinned template must be retained unchanged')


def inspect_suite(source, expected_sha):
    """Read a flat directory through its descriptor; no symlink following or code imports."""
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = os.listdir(fd)
        require(len(names) <= 512, 'TOO_MANY_MEMBERS', 'At most 512 suite files are accepted')
        bodies, total = {}, 0
        for name in names:
            require(bool(NAME.fullmatch(name)), 'SUITE_PATH_INVALID', 'Suite names must be flat and non-hidden')
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                require(stat.S_ISREG(os.fstat(child).st_mode), 'SUITE_NOT_FLAT', 'Suite members must be regular files')
                with os.fdopen(child, 'rb', closefd=False) as stream:
                    body = stream.read(MAX_FILE + 1)
                total += len(body)
                require(len(body) <= MAX_FILE and total <= MAX_TOTAL,
                        'SUITE_TOO_LARGE', 'Suite exceeds the bounded file or total size')
                bodies[name] = body
            finally:
                os.close(child)
        require(MANIFEST in bodies, 'MANIFEST_MISSING', 'The exact package manifest is required')
        pinned(bodies[MANIFEST], expected_sha)
        manifest = parse(bodies[MANIFEST])
        require(isinstance(manifest, dict) and isinstance(manifest.get('members'), list),
                'MANIFEST_DIALECT_INVALID', 'Expected the filed template members-list dialect')
        listed = {MANIFEST}
        for row in manifest['members']:
            require(isinstance(row, dict), 'MEMBER_INVALID', 'Manifest members must be objects')
            name, size, sha = row.get('file'), row.get('bytes'), row.get('sha256')
            require(isinstance(name, str) and bool(NAME.fullmatch(name)) and name not in listed,
                    'MEMBER_PATH_INVALID', 'Member paths must be unique, flat and non-hidden')
            require(type(size) is int and 0 <= size <= MAX_FILE and isinstance(sha, str) and bool(HEX.fullmatch(sha)),
                    'MEMBER_PIN_INVALID', 'Each member needs an integer byte length and SHA-256')
            listed.add(name)
            require(name in bodies and len(bodies[name]) == size and digest(bodies[name]) == sha,
                    'MEMBER_CUSTODY_MISMATCH', 'Missing or changed suite member: ' + name)
        require(set(bodies) == listed, 'UNLISTED_SUITE_FILE', 'Every suite file must be manifest-bound')
        checkers = sorted(n for n in bodies if 'self' in n.lower() and 'check' in n.lower() and n.endswith('.py'))
        require(checkers == ['self_check.py'], 'CHECKER_SELECTION_INVALID', 'Only the exact self_check.py entry is supported')
        derived = manifest.get('derived_from')
        require(isinstance(derived, dict), 'TEMPLATE_PROFILE_INVALID', 'A declared template derivation is required')
        profile = derived.get('template')
        checker_sha = {'SUITE__TEMPLATE GEN 01': GEN01_CHECKER_SHA,
                       'SUITE__TEMPLATE GEN 02': GEN02_CHECKER_SHA}.get(profile)
        require(checker_sha is not None and digest(bodies['self_check.py']) == checker_sha,
                'CHECKER_NOT_PINNED', 'Only the two explicitly supported filed template checkers may execute')
        manifests = sorted(n for n in bodies if 'MANIFEST' in n.upper() and n.endswith('.json'))
        require(manifests[0] == MANIFEST, 'MANIFEST_SELECTION_INVALID', 'The prover must select the pinned package manifest')
        return bodies
    finally:
        os.close(fd)


def execute(args, cwd, log):
    # Pinned upstream tools invoke Python subprocesses. Keep their imports away
    # from suite files without changing any upstream source bytes.
    env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
    env.update(PYTHONSAFEPATH='1', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    with log.open('ab') as stream:
        proc = subprocess.Popen([sys.executable, '-I', '-B', *map(str, args)],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise Refusal('TOOL_DEADLINE_EXCEEDED', 'The fixed upstream tool exceeded 60 seconds')


def evaluate(mode, source, expected, workspace, result):
    require(os.name == 'posix' and sys.version_info >= (3, 11),
            'RUNTIME_UNSUPPORTED', 'Linux/POSIX with Python 3.11 or later is required')
    require(mode in ('verify', 'instantiate'), 'MODE_INVALID', 'Mode must be verify or instantiate')
    template_custody()
    suite = result / 'suite'
    log = result / 'tool.log'
    if mode == 'verify':
        bodies = inspect_suite(workspace_path(workspace, source), expected)
        suite.mkdir()
        for name, body in bodies.items():
            (suite / name).write_bytes(body)
    else:
        data = read_regular(workspace_path(workspace, source))
        pinned(data, expected)
        require(len(data) <= 100000, 'SPEC_TOO_LARGE', 'Instantiation JSON exceeds 100000 bytes')
        spec = parse(data)
        require(isinstance(spec, dict) and all(k in spec for k in REQUIRED)
                and set(spec) <= set(REQUIRED + OPTIONAL)
                and all(isinstance(v, str) and '\x00' not in v for v in spec.values()),
                'SPEC_FIELDS_INVALID', 'Supply only documented string fields; out and command overrides are refused')
        # argv, never a shell; paths and executable choices come only from this adapter.
        args = [TEMPLATE / 'instantiate.py']
        for key in REQUIRED + OPTIONAL:
            if key in spec:
                args.extend(['--' + key, spec[key]])
        args.extend(['--out', suite])
        rc = execute(args, result, log)
        require(rc == 0, 'INSTANTIATION_NON_ALLOW', 'The unchanged instantiator refused the supplied variables; see tool.log')
        expected = digest(read_regular(suite / MANIFEST))
        bodies = inspect_suite(suite, expected)
    rc = execute([TEMPLATE / 'prove_conformance.py', suite], result, log)
    after = inspect_suite(suite, expected)
    require(bodies == after, 'VALIDATION_MUTATED_INPUT', 'Read-only proof verification changed suite bytes')
    require(rc == 0, 'CONFORMANCE_NON_ALLOW', 'The unchanged prover returned non-conformance; see tool.log')
    return {'manifest_sha256': expected, 'member_count': len(bodies) - 1,
            'template_manifest_sha256': TEMPLATE_SHA, 'tool_log_sha256': digest(log.read_bytes())}


def main():
    # No input is interpolated into shell syntax or GitHub workflow commands.
    result = Path(tempfile.mkdtemp(prefix='stegverse-suite-', dir=os.environ.get('RUNNER_TEMP')))
    report = {'schema': 'stegverse.suite-action-result/v1', 'verdict': 'FAIL_CLOSED',
              'authority_effect': 'NONE_SOURCE_VALIDATION_ONLY', 'native_execution_observed': False}
    mode = os.environ.get('SUITE_ACTION_MODE', 'verify')
    try:
        workspace = Path(os.environ.get('GITHUB_WORKSPACE', os.getcwd())).resolve(strict=True)
        prefix = 'SUITE_ACTION_SPEC' if mode == 'instantiate' else 'SUITE_ACTION_SOURCE'
        expected = os.environ.get('SUITE_ACTION_SPEC_SHA256' if mode == 'instantiate'
                                  else 'SUITE_ACTION_MANIFEST_SHA256', '')
        detail = evaluate(mode, os.environ.get(prefix, ''), expected, workspace, result)
        report.update(detail, verdict='CONFORMANT', mode=mode)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        report.update(failure_code=getattr(exc, 'code', 'INPUT_OR_IO_INVALID'),
                      failed_predicate=str(exc), required_evidence_or_repair='Correct the pinned source input or restore the exact filed template; inspect tool.log',
                      retry_entrypoint='the same action with the corrected independently reviewed SHA-256',
                      owning_existing_goal='BUILD-Q-56 (coordination ID; native binding UNBOUND)',
                      next_attempt='repeat source validation after the exact input condition is repaired')
    target = result / 'result.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    outputs = {'verdict': report['verdict'], 'report-path': str(target),
               'result-directory': str(result), 'manifest-sha256': report.get('manifest_sha256', '')}
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            for key, value in outputs.items():
                require('\n' not in value and '\r' not in value, 'OUTPUT_PATH_INVALID', 'Output values must be single-line')
                stream.write(key + '=' + value + '\n')
    print(json.dumps({'verdict': report['verdict'], 'report_path': str(target)}))
    return 0 if report['verdict'] == 'CONFORMANT' else 1


if __name__ == '__main__':
    sys.exit(main())
