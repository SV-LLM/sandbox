import unittest
import index_runner as r


class Tests(unittest.TestCase):
    def test_malformed_provider_and_checker_shapes_are_not_success(self):
        with self.assertRaises(ValueError):
            r.extract('agent402',{'sellers':[{'origin':'self','homepage':'https://agent.example','tools':None}]})
        self.assertEqual(r.verdict({'http_status':200,'document':{'proof':{'record_state':'verified','replay':'MATCH'}}}),'UNKNOWN')

    def test_asserted_not_verified_and_absence_needs_checked_locations(self):
        for state in ['asserted','discovered']:
            self.assertEqual(r.verdict({'http_status':200,'document':{'proof':{'record_state':state,'replay':{'verdict':'MATCH'}}}}),'RECORD_PRESENT_NOT_RECOMPUTED')
        doc={'proof':{'record_state':'none','publishes_replayable_record':False,'negative_result':'NOT_FOUND_IN_CHECKED_LOCATIONS','checked':[]}}
        self.assertEqual(r.verdict({'http_status':200,'document':doc}),'UNKNOWN')
        doc['proof']['checked']=[{'location':'x'}]
        self.assertEqual(r.verdict({'http_status':200,'document':doc}),'ABSENT_IN_CHECKED_LOCATIONS')

    def test_rate_limited_stops_without_retry(self):
        calls=[]
        def fake(url):calls.append(url);return {'http_status':429}
        rows,rate=r.probe([{'resource':'https://a.example/x'},{'resource':'https://b.example/x'}],2,fake,100)
        self.assertEqual(len(calls),1);self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['verdict'],'REFUSED_OR_ERROR');self.assertEqual(rate['next_not_before_epoch'],160)

    def test_batch_bound_cannot_be_removed(self):
        for limit in [0,21,-1,True]:
            with self.assertRaises(ValueError):r.probe([],limit)

    def test_source_error_is_not_empty(self):
        reports,rows=r.enumerate_catalogs(lambda u:{'http_status':401,'document':{'error':'auth required'}})
        self.assertEqual(rows,[]);self.assertEqual(len(reports),6)
        self.assertTrue(all(x['state']=='UNAVAILABLE_OR_UNRECOGNIZED_NOT_EMPTY' for x in reports))

    def test_catalog_facts_unknown_units_and_agent_routes(self):
        rows=r.extract('agent402',{'sellers':[{'origin':'self','homepage':'https://agent.example','network':'base','tools':[{'route':'/api/x','price':0.01}]}]})
        self.assertEqual(rows[0]['resource'],'https://agent.example/api/x')
        self.assertEqual(rows[0]['advertised_terms'],{'price':0.01})
        self.assertEqual(rows[0]['seller_advertised_terms'],{'network':'base'})

    def test_round_robin_and_duplicate_ads_preserved(self):
        def fake(u):
            name=next(k for k,v in r.SOURCES.items() if v==u)
            if name=='scriptmasterlabs':doc={'resources':[{'resource':'https://same.example','accepts':[{'amount':'2'}]}]}
            elif name=='agora':doc={'agents':[{'url':'https://same.example','price':'$1'}]}
            elif name=='agent402':doc={'sellers':[]}
            elif name=='cdp-bazaar':doc={'items':[]}
            else:doc={'data':[]}
            return {'http_status':200,'document':doc}
        reports,rows=r.enumerate_catalogs(fake)
        self.assertEqual(len(rows),1);self.assertEqual(len(rows[0]['advertisements']),2)

    def test_checker_query_is_encoded_and_target_never_fetched(self):
        calls=[]
        def fake(u):calls.append(u);return {'http_status':503}
        url='https://target.example/x?evil=https://elsewhere/#x'
        rows,_=r.probe([{'resource':url}],1,fake,0)
        self.assertTrue(calls[0].startswith(r.CHECKER+'?'))
        self.assertEqual(r.urllib.parse.parse_qs(r.urllib.parse.urlsplit(calls[0]).query),{'url':[url]})

    def test_bad_url_and_unsafe_html(self):
        self.assertFalse(r.valid_url('javascript:alert(1)'));self.assertFalse(r.valid_url('https://user:pass@example.com'))
        rep={'scope':'<script>','generated_at':'x','verdict_distribution':{},'discovery_sources':[],'rows':[]}
        self.assertNotIn('<script>',r.render(rep));self.assertIn('&lt;script&gt;',r.render(rep))


if __name__=='__main__':unittest.main()
