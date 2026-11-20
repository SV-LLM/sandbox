import importlib.util
import copy
import io
import json
import pathlib
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('check',pathlib.Path(__file__).parents[1]/'scripts/q55_return_contract.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def inputs(collision=False,action='TARGET-REPLACEMENT',existing=True):
    data=[b'new-one',b'new-two'] if collision else [b'new-one']
    req={'census_sha256':'c'*64,'native_revision':'a'*40,'payload_requests':[]}
    ret={'request':{},'census_sha256':'c'*64,'native_revision':'a'*40,'payloads':[]}
    for i,b in enumerate(data):
        digest=m.sha(b);path='tree/source'+str(i)
        req['payload_requests'].append({'sha256':digest,'bytes':len(b),'workspace_paths':[path]})
        ret['payloads'].append({'sha256':digest,'bytes':len(b),'status':'RETURNED','bundle_path':'payloads/'+digest,
            'workspace_paths':[{'path':path,'target':'target.py','disposition':action}]})
    raw=json.dumps(req).encode();ret['request']['sha256']=m.sha(raw)
    z=io.BytesIO()
    with zipfile.ZipFile(z,'w') as f:
        f.writestr('RETURN__MANIFEST__01.json',json.dumps(ret))
        for b in data:f.writestr('payloads/'+m.sha(b),b)
    tree={'truncated':False,'tree':[{'path':'target.py','mode':'100644','type':'blob','sha':'b'*40}] if existing else []}
    return raw,z.getvalue(),tree


def amended_inputs(unamended=False):
    q,z,t=inputs(collision=True)
    if unamended:
        req=json.loads(q)
        with zipfile.ZipFile(io.BytesIO(z)) as f:
            ret=json.loads(f.read('RETURN__MANIFEST__01.json'))
            payloads={n:f.read(n) for n in f.namelist() if n.startswith('payloads/')}
        data=b'unchosen existing target';digest=m.sha(data)
        req['payload_requests'].append({'sha256':digest,'bytes':len(data),'workspace_paths':['tree/unamended']})
        ret['payloads'].append({'sha256':digest,'bytes':len(data),'status':'RETURNED','bundle_path':'payloads/'+digest,
            'workspace_paths':[{'path':'tree/unamended','target':'other.py','disposition':'TARGET-REPLACEMENT'}]})
        q=json.dumps(req).encode();ret['request']['sha256']=m.sha(q)
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as f:
            f.writestr('RETURN__MANIFEST__01.json',json.dumps(ret))
            for n,b in payloads.items():f.writestr(n,b)
            f.writestr('payloads/'+digest,data)
        z=out.getvalue();t['tree'].append({'path':'other.py','mode':'100644','type':'blob','sha':'7'*40})
    prior=m.evaluate(q,z,t,m.sha(q),m.sha(z),'d'*40)
    prior_bytes=json.dumps(prior).encode()
    with zipfile.ZipFile(io.BytesIO(z)) as f:
        manifest_bytes=f.read('RETURN__MANIFEST__01.json')
        manifest=json.loads(manifest_bytes)
    changes=[]
    for i,p in enumerate(manifest['payloads'][:2]):
        changes.append({'workspace_path':'tree/source'+str(i),'sha256':p['sha256'],
                        'was':'TARGET-REPLACEMENT','now':'ARCHIVAL' if i else 'TARGET-REPLACEMENT',
                        **({'role':'CHOSEN'} if not i else {})})
    a={'schema':'stegverse.q55-target-contract-amendment/v1',
       'source_pins_unchanged':{'payload_request_sha256':m.sha(q),
          'workspace_census_sha256':'c'*64,'return_archive':'ZIP, SHA-256 '+m.sha(z),
          'original_return_manifest_sha256':m.sha(manifest_bytes),
          'consume_result':'SV-LLM/sandbox PR59 result, SHA-256 '+m.sha(prior_bytes)+
             ', native_revision_observed '+'d'*40+', PR59 head '+'e'*40},
       'decisions':[{'target':'target.py','native_blob':'b'*40,'decision':'CHOSEN: owner lineage',
                     'amended':changes}],
       'amended_disposition_counts':{'TARGET-REPLACEMENT':2 if unamended else 1,'ARCHIVAL':1,'total_paths':3 if unamended else 2}}
    return q,z,t,a,prior_bytes


class Tests(unittest.TestCase):
    def run_case(self,**kwargs):
        q,z,t=inputs(**kwargs);return m.evaluate(q,z,t,m.sha(q),m.sha(z),'d'*40)
    def test_clear_replacement_remains_source_only(self):
        r=self.run_case();self.assertTrue(r['target_contract_consistent']);self.assertFalse(r['source_import_performed']);self.assertFalse(r['full_migration_verified'])
    def test_conflicting_versions_refused(self):
        r=self.run_case(collision=True);self.assertFalse(r['target_contract_consistent']);self.assertIn('MULTIPLE_DIFFERENT_PAYLOADS_ONE_TARGET',r['findings'][0]['conditions'])
    def test_add_to_existing_refused(self):
        r=self.run_case(action='TARGET-ADD');self.assertIn('TARGET_ADD_ALREADY_EXISTS',r['findings'][0]['conditions'])
    def test_missing_replacement_refused(self):
        r=self.run_case(existing=False);self.assertIn('TARGET_REPLACEMENT_ABSENT',r['findings'][0]['conditions'])
    def test_wrong_pin_and_truncated_tree_refused(self):
        q,z,t=inputs()
        with self.assertRaises(ValueError):m.evaluate(q,z,t,'0'*64,m.sha(z),'d'*40)
        t['truncated']=True
        with self.assertRaises(ValueError):m.evaluate(q,z,t,m.sha(q),m.sha(z),'d'*40)
    def test_traversal_and_symlink_target_refused(self):
        for path in ['../secret','/absolute','x/../y','x\\y']:
            with self.assertRaises(ValueError):m.safe(path)
        q,z,t=inputs();t['tree'][0]['mode']='120000'
        r=m.evaluate(q,z,t,m.sha(q),m.sha(z),'d'*40);self.assertIn('TARGET_NOT_REGULAR_FILE',r['findings'][0]['conditions'])


class AmendmentTests(unittest.TestCase):
    def run_amended(self,mutate=lambda a:None,tree_change=None,prior_bytes_override=None):
        q,z,t,a,prior=amended_inputs();mutate(a)
        if tree_change:tree_change(t)
        raw=json.dumps(a).encode()
        return m.evaluate(q,z,t,m.sha(q),m.sha(z),'f'*40,raw,m.sha(raw),
                          prior if prior_bytes_override is None else prior_bytes_override)

    def test_pinned_overlay_resolves_collision_without_source_import(self):
        r=self.run_amended();self.assertTrue(r['target_contract_consistent'])
        self.assertEqual(r['disposition_counts'],{'TARGET-REPLACEMENT':1,'ARCHIVAL':1})
        self.assertEqual(r['returned_payloads_verified'],2)
        self.assertFalse(r['source_import_performed']);self.assertFalse(r['source_target_mapping_verified'])
        self.assertFalse(r['full_migration_verified'])

    def test_unknown_duplicate_or_different_source_row_refused(self):
        for change in [lambda a:a['decisions'][0]['amended'][0].update(workspace_path='../escape'),
                       lambda a:a['decisions'][0]['amended'][0].update(workspace_path='tree/unknown'),
                       lambda a:a['decisions'][0]['amended'][0].update(sha256='0'*64),
                       lambda a:a['decisions'][0]['amended'][0].update(was='TARGET-ADD'),
                       lambda a:a['decisions'][0]['amended'].append(copy.deepcopy(a['decisions'][0]['amended'][0]))]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_amended(change)

    def test_amendment_and_prior_result_pins_required(self):
        q,z,t,a,prior=amended_inputs();raw=json.dumps(a).encode()
        with self.assertRaises(ValueError):m.evaluate(q,z,t,m.sha(q),m.sha(z),'f'*40,raw,'0'*64,prior)
        with self.assertRaises(ValueError):self.run_amended(prior_bytes_override=prior+b' ')
        with self.assertRaises(ValueError):m.evaluate(q,z,t,m.sha(q),m.sha(z),'f'*40,None,m.sha(raw),prior)

    def test_source_lineage_and_prior_native_blob_refused(self):
        for change in [lambda a:a['source_pins_unchanged'].update(payload_request_sha256='0'*64),
                       lambda a:a['source_pins_unchanged'].update(original_return_manifest_sha256='0'*64),
                       lambda a:a['source_pins_unchanged'].update(return_archive='ZIP, SHA-256 '+'0'*64),
                       lambda a:a['decisions'][0].update(native_blob='0'*40)]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_amended(change)

    def test_incomplete_choices_counts_and_duplicate_target_refused(self):
        for change in [lambda a:a['decisions'][0]['amended'][1].update(now='TARGET-REPLACEMENT'),
                       lambda a:a['decisions'][0]['amended'][0].pop('role'),
                       lambda a:a['amended_disposition_counts'].update(ARCHIVAL=9),
                       lambda a:a['decisions'].append(copy.deepcopy(a['decisions'][0]))]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_amended(change)

    def test_native_stands_requires_no_active_payload_and_retains_current_readme(self):
        def archive(a):
            a['decisions'][0]['decision']='NOT-APPLIED — native stands'
            for x in a['decisions'][0]['amended']:x.update(now='ARCHIVAL');x.pop('role',None)
            a['amended_disposition_counts']={'ARCHIVAL':2,'total_paths':2}
        r=self.run_amended(archive,lambda t:t['tree'][0].update(sha='9'*40))
        self.assertTrue(r['target_contract_consistent']);self.assertEqual(r['distinct_targets'],0)
        self.assertTrue(r['amendment']['decisions'][0]['native_stands'])
        with self.assertRaises(ValueError):self.run_amended(lambda a:a['decisions'][0].update(decision='NOT-APPLIED'))

    def test_active_target_drift_is_a_finding(self):
        r=self.run_amended(tree_change=lambda t:t['tree'][0].update(sha='9'*40))
        self.assertFalse(r['target_contract_consistent'])
        self.assertEqual(r['findings'][0]['conditions'],['CHOSEN_TARGET_NATIVE_PREDECESSOR_CHANGED'])

    def test_unamended_active_predecessor_drift_refused_and_unchanged_passes(self):
        q,z,t,a,prior=amended_inputs(unamended=True);raw=json.dumps(a).encode()
        def evaluate():return m.evaluate(q,z,t,m.sha(q),m.sha(z),'f'*40,raw,m.sha(raw),prior)
        self.assertTrue(evaluate()['target_contract_consistent'])
        t['tree'][1]['sha']='8'*40
        r=evaluate();self.assertFalse(r['target_contract_consistent'])
        self.assertEqual(r['findings'],[{'target':'other.py',
            'conditions':['ACTIVE_TARGET_NATIVE_PREDECESSOR_CHANGED'],
            'candidate_hashes':[m.sha(b'unchosen existing target')]}])

    def test_unknown_archival_role_refused(self):
        for role in ['ARCHIVAL','anything',None,False,{},[]]:
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'unknown amendment role'):
                self.run_amended(lambda a:a['decisions'][0]['amended'][1].update(role=role))

    def test_malformed_direct_amendment_inputs_raise_value_error(self):
        q,z,t,a,prior=amended_inputs()
        variants=[[],None,{},dict(a,source_pins_unchanged=None),dict(a,decisions=[None]),
                  dict(a,decisions=[{'target':'target.py'}])]
        for malformed in variants:
            raw=json.dumps(malformed).encode()
            with self.subTest(malformed=malformed),self.assertRaises(ValueError):
                m.evaluate(q,z,t,m.sha(q),m.sha(z),'f'*40,raw,m.sha(raw),prior)


if __name__=='__main__':unittest.main()
