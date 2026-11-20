"""Minimal caller/retention seam for the existing receipt_client result shape.

The caller supplies one already-authorized existing submission function.
No wallet, credential, payment signer, endpoint or retry policy is created here.
"""
import hashlib
import json
import pathlib
import re


def cross_and_retain(submit_once, directory):
    root = pathlib.Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    reservation = root / 'submission-reservation.json'
    # Exclusive reservation makes an ambiguous effect non-replayable by default.
    with reservation.open('x', encoding='utf-8') as f:
        json.dump({'state':'RESERVED','retry':'reconcile existing result before another submission'},f)
    try:
        result = submit_once()
    except Exception:
        (root/'ambiguous.json').write_text(json.dumps({
            'failure_code':'CALL_OUTCOME_NOT_ESTABLISHED',
            'next_attempt':'reconcile original call through existing owner; do not resubmit blindly'})+'\n')
        raise
    if not isinstance(result, dict):
        raise ValueError('submission result must be an object; reservation remains')
    sensitive={'priv_hex','private_key','secret','api_key','access_token','seed','mnemonic','authorization','x-payment','payment-signature'}
    def contains_secret(value):
        if isinstance(value,dict):
            return any(str(k).lower() in sensitive or contains_secret(v) for k,v in value.items())
        return isinstance(value,list) and any(contains_secret(v) for v in value)
    if contains_secret(result):
        raise ValueError('credential-shaped result refused; reservation remains')
    # Retain NON-ALLOW and errors too. Never store credentials in the supplied result.
    data = (json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
    path = root/'crossing-result.json'
    with path.open('xb') as f:f.write(data)
    return {'result':result,'retained_path':str(path),
            'retained_sha256':hashlib.sha256(data).hexdigest(),
            'pair_id':result.get('pair_id'),'evidence_state':'CALLER_RESULT_RETAINED_NOT_CHAIN_VERIFIED'}


def retain_pair_from_export(export_path, pair_id, directory):
    if not isinstance(pair_id,str) or not re.fullmatch(r'PAIR-[0-9]{6}',pair_id):
        raise ValueError('invalid pair id')
    lines=pathlib.Path(export_path).read_bytes().splitlines(keepends=True)
    matching=[raw for raw in lines if json.loads(raw)['content'].get('pair_id')==pair_id]
    if len(matching)!=2:raise ValueError('two pair members not found')
    root=pathlib.Path(directory);root.mkdir(parents=True,exist_ok=True)
    output=root/(pair_id+'.ndjson');data=b''.join(matching)
    with output.open('xb') as f:f.write(data)
    return {'path':str(output),'sha256':hashlib.sha256(data).hexdigest(),
            'note':'slice retains exact stored lines; verify against full export and retained anchor'}
