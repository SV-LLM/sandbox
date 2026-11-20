#!/usr/bin/env python3
"""Verify kit byte pins, then run the exact published verifier on local bytes.
Network access is disabled for the replay call; no paid request is possible.
"""
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parent


def verify(root=ROOT):
    root=pathlib.Path(root).resolve();manifest=json.loads((root/'KIT_MANIFEST.json').read_text())
    for item in manifest['files']:
        path=(root/item['path']).resolve()
        if root not in path.parents or path.is_symlink():raise ValueError('unsafe kit member')
        data=path.read_bytes()
        if len(data)!=item['bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise ValueError('kit member mismatch: '+item['path'])
    published=json.loads((root/'bundle/manifest.json').read_text())
    verifier=root/'bundle/verifier.py';export=root/'bundle/export.ndjson'
    if hashlib.sha256(verifier.read_bytes()).hexdigest()!=published['verifier']['sha256']:
        raise ValueError('published verifier digest differs')
    if len(export.read_bytes())!=published['export_bytes']:raise ValueError('export length differs')
    spec=importlib.util.spec_from_file_location('pinned_public_verifier',verifier)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=io.StringIO()
    with (patch('urllib.request.urlopen',side_effect=RuntimeError('OFFLINE_REPLAY_NETWORK_DISABLED')),
          redirect_stdout(output)):
        code=module.main(['verifier.py',str(export),'--manifest',str(root/'bundle/manifest.json'),
                          '--anchor',manifest['expected_terminal_anchor']])
    return code,output.getvalue()


if __name__=='__main__':
    try:
        code,text=verify();print(text,end='');raise SystemExit(code)
    except Exception as exc:
        print('KIT_NON_ALLOW:',type(exc).__name__,str(exc));raise SystemExit(1)
