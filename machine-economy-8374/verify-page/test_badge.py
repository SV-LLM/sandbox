import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch
import verdict_badge as b
import verify

VERIFIED={'proof':{'record_state':'verified','replay':{'verdict':'MATCH'}}}
ABSENT={'proof':{'record_state':'none','publishes_replayable_record':False,
    'negative_result':'NOT_FOUND_IN_CHECKED_LOCATIONS','checked':[{'location':'x'}]}}


class Tests(unittest.TestCase):
    def test_three_canonical_cases_and_exact_resource_scope(self):
        cache=b.BadgeCache(lambda:0,lambda:0)
        cache.record('https://own.example/crossing',VERIFIED);cache.record('https://listed.example/paid',ABSENT)
        self.assertEqual(cache.observation('https://own.example/crossing')[0],'Replay-Verified')
        self.assertEqual(cache.observation('https://listed.example/paid')[0],'no replayable record')
        self.assertEqual(cache.observation('https://unprobed.example')[0],'not checked')
        self.assertEqual(cache.observation('https://own.example/other')[0],'not checked')

    def test_stale_and_evicted_unknown(self):
        at=[0];cache=b.BadgeCache(lambda:at[0],lambda:0);cache.record('x',VERIFIED)
        at[0]=300;self.assertEqual(cache.observation('x')[0],'not checked')
        for i in range(300):cache.record(str(i),VERIFIED)
        self.assertEqual(len(cache.entries),256);self.assertEqual(cache.observation('0')[0],'not checked')

    def test_assertion_not_verified_and_failure_supersedes_old_success(self):
        self.assertEqual(b.label({'proof':{'record_state':'asserted','replay':{'verdict':'MATCH'}}}),'record present')
        cache=b.BadgeCache();cache.record('x',VERIFIED);cache.record('x',{'failure_code':'VERIFY_CHECK_FAILED'})
        self.assertEqual(cache.observation('x')[0],'not checked')

    def test_false_absence_and_malformed_shapes(self):
        for value in [None,[],{'proof':[]},{'proof':{'record_state':'verified','replay':'MATCH'}},{'proof':{'record_state':'none'}}]:
            self.assertEqual(b.label(value),'not checked')

    def test_svg_never_includes_target_or_external_text(self):
        cache=b.BadgeCache();target='https://x.example/<script>&x'
        cache.record(target,{'proof':{'record_state':'<script>'}})
        svg=cache.svg(target).decode();self.assertNotIn('<script>',svg);self.assertNotIn(target,svg)
        self.assertIn('not checked',svg)

    def test_existing_http_handler_updates_cache_and_serves_three_cases(self):
        cache=b.BadgeCache()
        def check(url):return VERIFIED if 'own.example' in url else ABSENT
        with patch.object(verify,'BADGES',cache),patch.object(verify,'run_check',check):
            server=ThreadingHTTPServer(('127.0.0.1',0),verify.H)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                for target,want in [('https://own.example/crossing','Replay-Verified'),('https://listed.example/paid','no replayable record')]:
                    q=urllib.parse.urlencode({'url':target})
                    with urllib.request.urlopen(base+'/verify/check?'+q) as r:self.assertEqual(r.status,200)
                    with urllib.request.urlopen(base+'/badge?'+q) as r:
                        self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertIn(want,r.read().decode())
                with urllib.request.urlopen(base+'/badge?url=https://unprobed.example') as r:self.assertIn('not checked',r.read().decode())
                with urllib.request.urlopen(base+'/receipt-discovery') as r:self.assertIn('Current',r.read().decode())
            finally:server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':unittest.main()
