import pathlib
import tempfile
import unittest
import pilot_integration as p


class Tests(unittest.TestCase):
    def test_single_call_retains_refusal_and_does_not_replay(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[]
            def call():calls.append(1);return {'disposition':'FAIL_CLOSED','pair_id':'PAIR-000001','detail':{'failure_code':'X'}}
            r=p.cross_and_retain(call,d)
            self.assertEqual(r['result']['disposition'],'FAIL_CLOSED')
            self.assertTrue(pathlib.Path(r['retained_path']).exists())
            with self.assertRaises(FileExistsError):p.cross_and_retain(call,d)
            self.assertEqual(len(calls),1)

    def test_ambiguous_effect_keeps_reservation_no_retry(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[]
            def call():calls.append(1);raise TimeoutError('outcome unknown')
            with self.assertRaises(TimeoutError):p.cross_and_retain(call,d)
            self.assertTrue((pathlib.Path(d)/'ambiguous.json').exists())
            with self.assertRaises(FileExistsError):p.cross_and_retain(call,d)
            self.assertEqual(len(calls),1)

    def test_credential_shaped_result_never_written(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):p.cross_and_retain(lambda:{'nested':{'priv_hex':'fixture-secret'}},d)
            self.assertFalse((pathlib.Path(d)/'crossing-result.json').exists())

    def test_pair_slice_preserves_exact_lines_and_rejects_path(self):
        root=pathlib.Path(__file__).parent
        with tempfile.TemporaryDirectory() as d:
            r=p.retain_pair_from_export(root/'bundle/export.ndjson','PAIR-000040',d)
            raw=pathlib.Path(r['path']).read_bytes()
            self.assertEqual(len(raw.splitlines()),2)
            with self.assertRaises(ValueError):p.retain_pair_from_export(root/'bundle/export.ndjson','../x',d)


if __name__=='__main__':unittest.main()
