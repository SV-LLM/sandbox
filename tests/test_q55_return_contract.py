import importlib.util
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


if __name__=='__main__':unittest.main()
