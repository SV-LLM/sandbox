#!/usr/bin/env python3
"""Compare an explicitly pinned Q55 source census with immutable Git bytes.

This tool reads source objects only. It neither imports files nor guesses a
deployment path from a matching hash. Exit 2 means exact source payloads remain.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

TREES = frozenset(('machine-economy-endpoint', 'machine-economy-entry-suite',
                   'machine-economy-transfer', 'lane-callsite-8374', 'chain-export'))
SHA256 = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')
SENSITIVE = re.compile(r'(^|[_.-])(private[_-]?key|wallet[_-]?key|signing[_-]?key|'
                       r'tunnel[_-]?(token|credentials?)|mnemonic|secrets?)([_.-]|$)', re.I)


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def unique_pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'duplicate JSON key: ' + key)
        out[key] = value
    return out


def parse_census(data, expected_sha):
    require(isinstance(expected_sha, str) and bool(SHA256.fullmatch(expected_sha)), 'explicit lowercase census SHA-256 required')
    require(len(data) <= 4 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == expected_sha, 'census size or SHA-256 mismatch')
    doc = json.loads(data, object_pairs_hook=unique_pairs)
    require(isinstance(doc, dict) and doc.get('census') == 'WORKSPACE__SOURCE__CENSUS__Q55__01', 'unknown census dialect')
    trees, entries, extensions = doc.get('trees'), doc.get('entries'), doc.get('allowlist_extensions')
    require(isinstance(trees, list) and len(trees) == len(TREES) and set(trees) == TREES, 'exact five Q55 source trees required')
    require(isinstance(extensions, list) and bool(extensions)
            and all(isinstance(x, str) and x.startswith('.') for x in extensions), 'extension allowlist required')
    require(isinstance(entries, list) and bool(entries) and len(entries) <= 20000
            and type(doc.get('entry_count')) is int and doc['entry_count'] == len(entries), 'nonempty complete entry denominator required')
    require(type(doc.get('excluded_count')) is int and doc['excluded_count'] >= 0, 'explicit exclusion count required')
    seen = set()
    for row in entries:
        require(isinstance(row, dict) and set(row) == {'path', 'size', 'sha256'}, 'each source row must contain exactly path/size/sha256; no payload or authority fields')
        name, size, sha = row['path'], row['size'], row['sha256']
        require(isinstance(name, str) and name and '\\' not in name and not any(ord(c) < 32 for c in name), 'unsafe source path')
        parts = name.split('/')
        require(len(parts) >= 2 and parts[0] in TREES and all(p not in ('', '.', '..') for p in parts), 'source path must stay in one named tree')
        require(not PurePosixPath(name).is_absolute() and name not in seen, 'absolute or duplicate source path')
        require(not any(p in ('__pycache__', '.git', '_Vault', 'SKAP', 'keys') for p in parts)
                and not SENSITIVE.search(parts[-1]), 'custody/cache path is outside this source-only comparison')
        require(any(name.endswith(ext) for ext in extensions), 'source extension outside producer allowlist')
        require(type(size) is int and 0 <= size <= 64 * 1024 * 1024
                and isinstance(sha, str) and bool(SHA256.fullmatch(sha)), 'invalid source byte length or hash')
        seen.add(name)
    return doc


def git(repo, *args, data=None):
    return subprocess.check_output(['git', '-C', str(repo), *args], input=data, stderr=subprocess.PIPE)


def native_index(repo, revision):
    require(bool(COMMIT.fullmatch(revision)), 'an immutable 40-hex Git commit is required')
    resolved = git(repo, 'rev-parse', '--verify', revision + '^{commit}').decode().strip()
    require(resolved == revision, 'native commit resolution differs')
    listing = git(repo, 'ls-tree', '-r', '-z', revision)
    objects = defaultdict(list)
    skipped_modes = Counter()
    for row in listing.split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, sha = meta.decode('ascii').split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            skipped_modes[mode] += 1
            continue
        objects[sha].append({'path': name.decode('utf-8'), 'mode': mode})
    shas = sorted(objects)
    stream = git(repo, 'cat-file', '--batch', data=('\n'.join(shas) + '\n').encode()) if shas else b''
    offset, index = 0, defaultdict(list)
    for requested in shas:
        end = stream.index(b'\n', offset)
        sha, kind, size = stream[offset:end].decode('ascii').split()
        size = int(size)
        require(sha == requested and kind == 'blob', 'unexpected native object response')
        body = stream[end + 1:end + 1 + size]
        require(len(body) == size and stream[end + 1 + size:end + 2 + size] == b'\n', 'truncated native object')
        actual = hashlib.sha1(('blob ' + str(size) + '\0').encode() + body).hexdigest()
        require(actual == sha, 'native Git blob identity mismatch')
        key = (size, hashlib.sha256(body).hexdigest())
        index[key].extend(dict(item, git_blob_sha1=sha) for item in objects[sha])
        offset = end + 2 + size
    require(offset == len(stream), 'unconsumed native object data')
    for rows in index.values():
        rows.sort(key=lambda x: x['path'])
    return index, dict(skipped_modes)


def compare(data, expected_sha, repo, revision):
    doc = parse_census(data, expected_sha)
    index, skipped = native_index(repo, revision)
    rows, missing = [], defaultdict(list)
    coverage, tree_counts = Counter(), defaultdict(Counter)
    for row in sorted(doc['entries'], key=lambda x: x['path']):
        key = (row['size'], row['sha256'])
        matches = index.get(key, [])
        state = 'EXACT_NATIVE_BYTES_AVAILABLE' if matches else 'SOURCE_PAYLOAD_REQUIRED'
        coverage[state] += 1
        tree_counts[row['path'].split('/')[0]][state] += 1
        rows.append(dict(row, byte_state=state, native_matches=matches,
                         target_binding='NOT_ESTABLISHED_BY_BYTE_EQUALITY'))
        if not matches:
            missing[key].append(row['path'])
    requests = [{'bytes': size, 'sha256': sha, 'workspace_paths': names}
                for (size, sha), names in sorted(missing.items(), key=lambda x: x[1][0])]
    return {'schema': 'stegverse.q55-source-delta/v1', 'authority_effect': 'NONE_SOURCE_READBACK_ONLY',
            'census_sha256': expected_sha, 'native_revision': revision,
            'census_entries': len(rows), 'producer_reported_excluded_count': doc['excluded_count'],
            'byte_coverage': dict(coverage), 'by_tree': {k: dict(v) for k, v in sorted(tree_counts.items())},
            'unique_missing_payloads': len(requests), 'missing_payload_bytes': sum(x['bytes'] for x in requests),
            'source_target_mapping_verified': False, 'full_migration_verified': False,
            'native_nonregular_modes_excluded': skipped, 'rows': rows, 'payload_requests': requests}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--census', required=True, type=Path)
    parser.add_argument('--census-sha256', required=True)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        require(not args.census.is_symlink(), 'census symlink refused')
        report = compare(args.census.read_bytes(), args.census_sha256, args.repo, args.revision)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({k: report[k] for k in ('native_revision', 'census_entries', 'byte_coverage', 'unique_missing_payloads', 'missing_payload_bytes', 'full_migration_verified')}))
        return 2 if report['unique_missing_payloads'] else 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        failure = {'failure_code': 'Q55_CENSUS_OR_NATIVE_INPUT_INVALID',
                   'failed_predicate': str(exc), 'required_evidence_or_repair': 'Supply the exact source-only census pin and readable immutable native commit; preserve every source row',
                   'retry_entrypoint': 'the same CLI with corrected pinned inputs',
                   'owning_existing_goal': 'BUILD-Q-55 (coordination ID; native binding UNBOUND)',
                   'next_attempt': 'after the exact source input or native readback condition is repaired'}
        print(json.dumps(failure))
        return 1


if __name__ == '__main__':
    sys.exit(main())
