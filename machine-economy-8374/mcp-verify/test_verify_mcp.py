import email.message
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import battery
import build_package
import verify_mcp as m

ROOT = pathlib.Path(__file__).resolve().parent


class Response:
    def __init__(self, data, code=200, content_type="application/json", headers=None):
        self.raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.code = code
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type
        for k, v in (headers or {}).items():
            self.headers[k] = v
    def __enter__(self): return self
    def __exit__(self, *a): return None
    def read(self, n): return self.raw[:n]


class Tests(unittest.TestCase):
    def setUp(self):
        self.s = m.Server(lambda url: m.tool_result({"original_url": url}))

    def ready(self):
        self.s.handle(battery.requests("https://listed.example/x")[0])
        self.s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, args):
        return self.s.handle({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                              "params": {"name": m.TOOL["name"], "arguments": args}})

    def fetch(self, response, url="https://listed.example/x?evil=https://other.invalid/#x"):
        with patch.object(m.urllib.request, "build_opener") as op:
            op.return_value.open.return_value = response
            result = m.fetch_check(url)
            req = op.return_value.open.call_args.args[0]
            self.assertEqual(req.get_method(), "GET")
            parts = m.urllib.parse.urlsplit(req.full_url)
            self.assertEqual(parts.scheme + "://" + parts.netloc + parts.path, m.CHECKER)
            self.assertEqual(m.urllib.parse.parse_qs(parts.query), {"url": [url]})
            self.assertEqual(op.return_value.open.call_count, 1)
            self.assertIsInstance(op.call_args.args[0], m.NoRedirect)
            return result

    def test_lifecycle_no_work_before_initialized_notification(self):
        self.assertIn("error", self.call({"url": "x"}))
        self.s.handle(battery.requests("x")[0])
        self.assertIn("error", self.call({"url": "x"}))
        self.s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertFalse(self.call({"url": "x"})["result"]["isError"])

    def test_negotiation_and_reinitialize_refusal(self):
        req = battery.requests("x")[0]
        req["params"]["protocolVersion"] = "future-version"
        self.assertEqual(self.s.handle(req)["result"]["protocolVersion"], m.PROTOCOL)
        self.assertIn("error", self.s.handle(req))

    def test_ping_and_unknown_method(self):
        self.assertEqual(self.s.handle({"jsonrpc":"2.0", "id":1, "method":"ping"})["result"], {})
        self.ready()
        self.assertEqual(self.s.handle({"jsonrpc":"2.0", "id":1, "method":"execute"})["error"]["code"], -32601)

    def test_exact_arguments_refuse_override_and_controls(self):
        self.ready()
        for args in [{}, {"url": ""}, {"url": "x", "endpoint": "http://evil"},
                     {"url": 1}, {"url": "x\nHost: evil"}, {"url": "x"*8193}, []]:
            with self.subTest(args=str(args)[:50]):
                self.assertTrue(self.call(args)["result"]["isError"])

    def test_unknown_tool_notification_and_invalid_envelope(self):
        self.ready()
        self.assertIsNone(self.s.handle({"jsonrpc":"2.0", "method":"unknown"}))
        self.assertIn("error", self.s.handle([]))
        self.assertIn("error", self.s.handle({"jsonrpc":"2.0", "id":True, "method":"ping"}))
        self.assertIn("error", self.s.handle({"jsonrpc":"2.0", "id":1,"method":"tools/call", "params":{"name":"shell"}}))

    def test_forwards_asserted_without_reclassification(self):
        value = {"resource":"x", "proof":{"record_state":"asserted", "replay":{"verdict":"MATCH"}}}
        r = self.fetch(Response(value))
        self.assertEqual(r["structuredContent"]["result"], value)
        self.assertEqual(json.loads(r["content"][0]["text"]), r["structuredContent"])
        self.assertIn("NOT_WRAPPER_REPLAY", r["structuredContent"]["checker"]["evidence_class"])

    def test_refusal_and_rate_not_absence_or_retry(self):
        for status in (400,429,500):
            with self.subTest(status=status):
                v={"failure_code":"VERIFY_RATE_LIMIT" if status==429 else "VERIFY_SSRF_REFUSED"}
                r=self.fetch(Response(v,status,headers={"Retry-After":"60"}))
                self.assertTrue(r["isError"])
                self.assertEqual(r["structuredContent"]["result"],v)
                self.assertEqual(r["structuredContent"]["checker"]["retry_after"],"60")

    def test_nonjson_and_redirect_are_errors(self):
        for code in (200,302,403):
            r=self.fetch(Response(b"<html>no</html>",code,"text/html"))
            self.assertEqual(r["structuredContent"]["failure_code"],"VERIFY_CHECKER_NON_JSON")
            self.assertTrue(r["isError"])

    def test_malformed_scalar_duplicate_nonfinite_and_large_json(self):
        for raw in [b"{",b"[]",b'{"a":1,"a":2}',b'{"a":NaN}',b"x"*(m.MAX_RESPONSE+1)]:
            self.assertTrue(self.fetch(Response(raw))["isError"])

    def test_unreachable_is_not_absent(self):
        with patch.object(m.urllib.request,"build_opener") as op:
            op.return_value.open.side_effect=OSError("no network")
            r=m.fetch_check("https://listed.example")
            self.assertEqual(r["structuredContent"]["failure_code"],"VERIFY_CHECKER_UNREACHABLE")
            self.assertEqual(op.return_value.open.call_count,1)

    def test_no_redirect_handler(self):
        self.assertIsNone(m.NoRedirect().redirect_request(None,None,302,"",{},"https://evil"))

    def test_packaged_stdio_three_targets_preserves_contract(self):
        build_package.build()
        package=ROOT/"dist/stegverse-verify-mcp.pyz"
        # Test-only network fixture is installed before the actual zipapp __main__.
        harness='''import sys,runpy,urllib.request,urllib.parse,email.message,json
class R:
 def __init__(self,d,c=200):
  self.code=c;self.raw=json.dumps(d).encode();self.headers=email.message.Message();self.headers['Content-Type']='application/json'
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self,n):return self.raw[:n]
class O:
 def open(self,req,timeout):
  p=urllib.parse.urlsplit(req.full_url)
  if p.scheme+'://'+p.netloc+p.path!='https://8374.stegverse.org/verify/check':raise RuntimeError('wrong upstream')
  u=urllib.parse.parse_qs(p.query)['url'][0]
  if u.startswith('ftp:'):return R({'failure_code':'VERIFY_SSRF_REFUSED'},400)
  if u=='https://8374.stegverse.org/crossing':return R({'resource':u,'proof':{'record_state':'verified','replay':{'verdict':'MATCH','pairs':62,'entries':124,'terminal_anchor':'a'*64}}})
  return R({'resource':u,'proof':{'record_state':'none','publishes_replayable_record':False,'negative_result':'NOT_FOUND_IN_CHECKED_LOCATIONS','checked':[{'location':u,'result':'no record'}]}})
urllib.request.build_opener=lambda *a:O()
sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[1],run_name='__main__')
'''
        payload="".join(json.dumps(r)+"\n" for r in battery.requests("https://listed.example/x"))
        p=subprocess.run([sys.executable,"-I","-B","-c",harness,str(package)],
                         input=payload,text=True,capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stderr,"")
        messages=[json.loads(line) for line in p.stdout.splitlines()]
        self.assertEqual(len(messages),5)
        self.assertTrue(all(battery.evaluate(messages).values()))

    def test_packaged_oversized_and_malformed_frame(self):
        build_package.build()
        package=ROOT/"dist/stegverse-verify-mcp.pyz"
        for payload in ["{bad}\n", "x"*(m.MAX_MESSAGE+1)+"\n"]:
            p=subprocess.run([sys.executable,"-I","-B",str(package)],input=payload,
                             text=True,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout)["error"]["code"],-32700)

    def test_package_build_is_byte_deterministic(self):
        build_package.build()
        before={p.name:p.read_bytes() for p in (ROOT/"dist").iterdir()}
        build_package.build()
        self.assertEqual(before,{p.name:p.read_bytes() for p in (ROOT/"dist").iterdir()})

    def test_battery_rejects_fixture_absence_without_locations(self):
        messages=[{"id":3,"result":{"structuredContent":{"result":{"proof":{"record_state":"asserted","replay":{"verdict":"MATCH"}}}}}}]
        checks=battery.evaluate(messages)
        self.assertFalse(checks["own_verified_match"])
        self.assertFalse(checks["listed_absence_bounded"])


if __name__ == "__main__":
    unittest.main()
