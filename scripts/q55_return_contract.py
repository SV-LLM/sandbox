#!/usr/bin/env python3
"""Validate Q55 return bytes and target consistency without importing payloads."""
import argparse
import collections
import copy
import hashlib
import io
import json
import pathlib
import re
import zipfile


def sha(data):return hashlib.sha256(data).hexdigest()


def safe(path):
    if not isinstance(path,str) or not path or '\\' in path:
        raise ValueError('invalid path')
    p=pathlib.PurePosixPath(path)
    if p.is_absolute() or any(x in ('','..','.') for x in path.split('/')) or '.git' in p.parts:
        raise ValueError('unsafe path')
    return path


def amend_manifest(manifest, amendment_bytes, amendment_sha, prior_result_bytes,
                   request_sha, archive_sha, manifest_sha, census_sha):
    """Normalize malformed overlay inputs for direct callers as well as the CLI."""
    try:
        return _amend_manifest(manifest, amendment_bytes, amendment_sha, prior_result_bytes,
                               request_sha, archive_sha, manifest_sha, census_sha)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('malformed amendment or pinned prior result') from exc


def _amend_manifest(manifest, amendment_bytes, amendment_sha, prior_result_bytes,
                    request_sha, archive_sha, manifest_sha, census_sha):
    """Apply a pinned owner disposition overlay, preserving the returned bytes."""
    if not amendment_sha or sha(amendment_bytes) != amendment_sha:
        raise ValueError('amendment digest mismatch')
    a = json.loads(amendment_bytes)
    if a.get('schema') != 'stegverse.q55-target-contract-amendment/v1':
        raise ValueError('unknown amendment schema')
    pins = a['source_pins_unchanged']
    if (pins['payload_request_sha256'] != request_sha or
            pins['workspace_census_sha256'] != census_sha or
            pins['original_return_manifest_sha256'] != manifest_sha or
            not pins['return_archive'].endswith('SHA-256 ' + archive_sha)):
        raise ValueError('amendment source lineage differs')
    bound = re.search(r'SHA-256 ([0-9a-f]{64}), native_revision_observed '
                      r'([0-9a-f]{40}), PR59 head ([0-9a-f]{40})$', pins['consume_result'])
    if not bound or prior_result_bytes is None or sha(prior_result_bytes) != bound[1]:
        raise ValueError('pinned prior contract result required')
    prior = json.loads(prior_result_bytes)
    if (prior['native_revision_observed'] != bound[2] or
            prior['request_sha256'] != request_sha or
            prior['return_archive_sha256'] != archive_sha or
            prior['return_manifest_sha256'] != manifest_sha):
        raise ValueError('prior result lineage differs')
    old_targets = {x['target']: x for x in prior['targets']}
    amended = copy.deepcopy(manifest)
    by_path = {}
    for payload in amended['payloads']:
        for row in payload['workspace_paths']:
            if row['path'] in by_path:
                raise ValueError('duplicate original disposition path')
            by_path[row['path']] = (payload['sha256'], row)
    seen_paths = set()
    seen_targets = set()
    decisions = []
    for decision in a['decisions']:
        target = safe(decision['target'])
        if target in seen_targets or target not in old_targets:
            raise ValueError('duplicate or unknown amended target')
        seen_targets.add(target)
        if decision['native_blob'] != old_targets[target]['native_blob']:
            raise ValueError('amendment prior native blob differs')
        chosen = []
        for change in decision['amended']:
            path = safe(change['workspace_path'])
            if path in seen_paths or path not in by_path:
                raise ValueError('duplicate or unknown amendment path')
            seen_paths.add(path)
            digest, row = by_path[path]
            if (digest != change['sha256'] or row.get('target') != target or
                    row['disposition'] != change['was']):
                raise ValueError('amendment does not match original row')
            if change['now'] not in ('ARCHIVAL', 'TARGET-REPLACEMENT', 'TARGET-ADD'):
                raise ValueError('unknown amended disposition')
            if 'role' in change and change['role'] != 'CHOSEN':
                raise ValueError('unknown amendment role')
            row['disposition'] = change['now']
            if change.get('role') == 'CHOSEN':
                if change['now'] not in ('TARGET-REPLACEMENT', 'TARGET-ADD'):
                    raise ValueError('chosen payload must remain active')
                chosen.append(digest)
        active = [digest for digest, row in by_path.values()
                  if row.get('target') == target and row['disposition'].startswith('TARGET-')]
        native_stands = decision['decision'].startswith('NOT-APPLIED')
        if native_stands:
            if active or chosen:
                raise ValueError('native-stands decision retains active payload')
        elif (not decision['decision'].startswith('CHOSEN:') or len(chosen) != 1 or
              not active or set(active) != set(chosen)):
            raise ValueError('chosen decision lacks exactly one active hash')
        decisions.append({'target': target, 'native_stands': native_stands,
                          'chosen_sha256': chosen[0] if chosen else None,
                          'prior_native_blob': decision['native_blob']})
    counts = collections.Counter(row['disposition'] for _, row in by_path.values())
    expected = a['amended_disposition_counts']
    if expected.get('total_paths') != len(by_path) or any(
            counts.get(k, 0) != expected.get(k, 0)
            for k in set(counts) | (set(expected) - {'total_paths'})):
        raise ValueError('amended disposition counts differ')
    return amended, {'sha256': amendment_sha, 'prior_result_sha256': bound[1],
                     'prior_native_revision': bound[2], 'prior_source_head': bound[3],
                     'amended_paths': len(seen_paths), 'decisions': decisions}


def evaluate(request_bytes, archive_bytes, native_tree, request_sha, archive_sha, revision,
             amendment_bytes=None, amendment_sha=None, prior_result_bytes=None):
    if sha(request_bytes)!=request_sha or sha(archive_bytes)!=archive_sha:
        raise ValueError('input digest mismatch')
    if not re.fullmatch('[0-9a-f]{40}',revision) or native_tree.get('truncated') is not False:
        raise ValueError('immutable complete native tree required')
    request=json.loads(request_bytes)
    requested={}
    requested_paths=set()
    for p in request['payload_requests']:
        if p['sha256'] in requested:raise ValueError('duplicate requested payload')
        if type(p['bytes']) is not int or p['bytes']<0:raise ValueError('invalid payload size')
        for path in p['workspace_paths']:
            safe(path)
            if path in requested_paths:raise ValueError('duplicate requested path')
            requested_paths.add(path)
        requested[p['sha256']]=p
    nodes={x['path']:x for x in native_tree['tree']}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
        infos=z.infolist();names=[x.filename for x in infos]
        if len(names)!=len(set(names)) or sum(x.file_size for x in infos)>8*1024*1024:
            raise ValueError('duplicate or oversized archive')
        for name in names:safe(name)
        manifest_bytes=z.read('RETURN__MANIFEST__01.json');m=json.loads(manifest_bytes)
        if m['request']['sha256']!=request_sha or m['census_sha256']!=request['census_sha256']:
            raise ValueError('return not bound to requested census')
        if m['native_revision']!=request['native_revision']:
            raise ValueError('return native base differs from request')
        amendment = None
        if amendment_bytes is not None:
            m, amendment = amend_manifest(m, amendment_bytes, amendment_sha, prior_result_bytes,
                                         request_sha, archive_sha, sha(manifest_bytes), request['census_sha256'])
        elif amendment_sha is not None or prior_result_bytes is not None:
            raise ValueError('amendment bytes required for overlay inputs')
        seen=set();paths=set();targets=collections.defaultdict(list)
        returned=held=payload_bytes=0;dispositions=collections.Counter()
        for p in m['payloads']:
            digest=p['sha256']
            if digest in seen or digest not in requested:raise ValueError('duplicate or unknown returned payload')
            seen.add(digest);original=requested[digest]
            if p['bytes']!=original['bytes']:raise ValueError('return size differs from request')
            if {x['path'] for x in p['workspace_paths']}!=set(original['workspace_paths']):
                raise ValueError('return path aliases differ from request')
            if p['status']=='RETURNED':
                if p['bundle_path']!='payloads/'+digest:raise ValueError('payload path not bound to digest')
                data=z.read(p['bundle_path'])
                if len(data)!=p['bytes'] or sha(data)!=digest:raise ValueError('returned bytes mismatch')
                returned+=1;payload_bytes+=len(data)
            elif p['status']=='NOT_RETURNED_NOT_REQUIRED_LIVE_STATE':
                allowed={'machine-economy-endpoint/public-url.txt','machine-economy-endpoint/quote-cache.json'}
                if not set(original['workspace_paths'])<=allowed:raise ValueError('unrecognized live-state exclusion')
                held+=1
            else:raise ValueError('unknown return status')
            for x in p['workspace_paths']:
                source=safe(x['path'])
                if source in paths:raise ValueError('duplicate disposition path')
                paths.add(source);dispositions[x['disposition']]+=1
                kind=x['disposition']
                if kind in ('TARGET-ADD','TARGET-REPLACEMENT'):
                    if p['status']!='RETURNED':raise ValueError('unreturned payload assigned a target')
                    target=safe(x['target'])
                    targets[target].append({'workspace_path':source,'sha256':digest,'bytes':p['bytes'],'action':kind})
                elif kind not in ('ARCHIVAL','NOT-REQUIRED'):
                    raise ValueError('unknown disposition')
        if seen!=set(requested) or paths!=requested_paths:raise ValueError('incomplete return coverage')
    target_rows=[];findings=[]
    for target,choices in sorted(targets.items()):
        hashes=sorted({x['sha256'] for x in choices});node=nodes.get(target)
        reasons=[]
        if len(hashes)>1:reasons.append('MULTIPLE_DIFFERENT_PAYLOADS_ONE_TARGET')
        if any(x['action']=='TARGET-ADD' for x in choices) and node is not None:
            reasons.append('TARGET_ADD_ALREADY_EXISTS')
        if any(x['action']=='TARGET-REPLACEMENT' for x in choices) and node is None:
            reasons.append('TARGET_REPLACEMENT_ABSENT')
        if node and (node.get('type')!='blob' or node.get('mode') not in ('100644','100755')):
            reasons.append('TARGET_NOT_REGULAR_FILE')
        row={'target':target,'native_blob':node.get('sha') if node else None,
             'native_mode':node.get('mode') if node else None,'choices':choices,
             'distinct_payloads':len(hashes),'conditions':reasons}
        target_rows.append(row)
        if reasons:findings.append({'target':target,'conditions':reasons,'candidate_hashes':hashes})
    if amendment:
        for decision in amendment['decisions']:
            target = decision['target']; node = nodes.get(target)
            decision['current_native_blob'] = node.get('sha') if node else None
            if not decision['native_stands'] and decision['current_native_blob'] != decision['prior_native_blob']:
                findings.append({'target': target, 'conditions': ['CHOSEN_TARGET_NATIVE_PREDECESSOR_CHANGED'],
                                 'candidate_hashes': [decision['chosen_sha256']]})
        # Unamended active replacements carry the same pinned predecessor promise.
        prior_targets = {x['target']: x for x in json.loads(prior_result_bytes)['targets']}
        chosen_drift = {x['target'] for x in findings
                        if 'CHOSEN_TARGET_NATIVE_PREDECESSOR_CHANGED' in x['conditions']}
        for row in target_rows:
            if not any(x['action'] == 'TARGET-REPLACEMENT' for x in row['choices']):
                continue
            if row['target'] not in prior_targets:
                raise ValueError('active replacement missing from pinned prior result')
            if (row['native_blob'] != prior_targets[row['target']]['native_blob'] and
                    row['target'] not in chosen_drift):
                findings.append({'target': row['target'],
                                 'conditions': ['ACTIVE_TARGET_NATIVE_PREDECESSOR_CHANGED'],
                                 'candidate_hashes': sorted({x['sha256'] for x in row['choices']})})
    return {'schema':'stegverse.q55-return-contract-check/v1','authority':'NONE',
        'request_sha256':request_sha,'return_archive_sha256':archive_sha,
        'return_manifest_sha256':sha(manifest_bytes),'native_revision_observed':revision,
        'requested_payloads':len(requested),'returned_payloads_verified':returned,
        'returned_payload_bytes_verified':payload_bytes,'held_live_state_dispositions':held,
        'workspace_paths_dispositioned':len(paths),'disposition_counts':dict(dispositions),
        'target_rows':sum(len(v) for v in targets.values()),'distinct_targets':len(targets),
        'targets':target_rows,'findings':findings,'target_contract_consistent':not findings,
        'amendment':amendment,
        'source_import_performed':False,'source_target_mapping_verified':False,
        'full_migration_verified':False,
        'next_action':('Non-author exact-head review, then existing owner explicitly integrates the coherent source delta under fresh expected-head protection and deliberately refreshes package manifest; no import/runtime follows from this contract check.' if amendment and not findings else
                       'Original owner chooses one exact hash per conflicting target or archives/reassigns each older version; correct ADD to existing-path semantics; refresh native pin; independent review then explicit atomic source integration.')}


def main():
    p=argparse.ArgumentParser();p.add_argument('--request',required=True,type=pathlib.Path)
    p.add_argument('--return-zip',required=True,type=pathlib.Path);p.add_argument('--native-tree',required=True,type=pathlib.Path)
    p.add_argument('--request-sha256',required=True);p.add_argument('--return-sha256',required=True)
    p.add_argument('--revision',required=True);p.add_argument('--output',required=True,type=pathlib.Path)
    p.add_argument('--amendment',type=pathlib.Path);p.add_argument('--amendment-sha256')
    p.add_argument('--prior-result',type=pathlib.Path)
    a=p.parse_args()
    try:r=evaluate(a.request.read_bytes(),a.return_zip.read_bytes(),json.loads(a.native_tree.read_text()),a.request_sha256,a.return_sha256,a.revision,
                   a.amendment.read_bytes() if a.amendment else None, a.amendment_sha256,
                   a.prior_result.read_bytes() if a.prior_result else None)
    except Exception as exc:
        print(json.dumps({'failure_code':'Q55_RETURN_INPUT_NON_ALLOW','failed_predicate':str(exc),'required_evidence_or_repair':'exact pinned complete input and regular native targets','retry_entrypoint':'original Q55 return/PR54','owning_existing_goal':'BUILD-Q-55 coordination; native UNBOUND','next_attempt':'repair named input; never import unverified bytes'}));return 1
    a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k] for k in ['returned_payloads_verified','workspace_paths_dispositioned','distinct_targets','target_contract_consistent']}))
    return 0 if r['target_contract_consistent'] else 2


if __name__=='__main__':raise SystemExit(main())
