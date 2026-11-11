import json
import unittest
from unittest.mock import patch
from revision_receipt import record_terminal, failure_messages

class TerminalReceiptTests(unittest.TestCase):
    def capture(self,status,logs):
        writes=[]
        details={'deployment_uuid':'exact-deployment','status':status,'commit':'1'*40,'logs':logs}
        result=record_terminal('exact-deployment',details,lambda name,value:writes.append((name,value)))
        return result,writes

    def test_null_logs_preserve_every_exact_terminal_status(self):
        for status in ['finished','failed','cancelled','canceled']:
            result,writes=self.capture(status,None)
            self.assertEqual(result['status'],status)
            self.assertEqual(writes[0][1]['status'],status)
            self.assertEqual(writes[0][1]['deployment_uuid'],'exact-deployment')
            self.assertNotIn('syntheticFailureMessages',writes[0][1])

    def test_list_and_json_list_diagnostics(self):
        entries=[{'output':'build failed: synthetic'},None,{'output':None},{'output':42},'unexpected',{'output':'ok'}]
        for logs in [entries,json.dumps(entries)]:
            result,writes=self.capture('failed',logs)
            self.assertEqual(result['syntheticFailureMessages'],['build failed: synthetic'])
            self.assertEqual(writes[0][1]['status'],'failed')

    def test_map_scalar_null_and_invalid_json_are_optional(self):
        for logs in [{}, {'output':'error: must not dump map'},'null','{}','broken-json',42,False]:
            result,writes=self.capture('failed',logs)
            self.assertEqual(result['syntheticFailureMessages'],[])
            self.assertEqual(writes[0][1]['status'],'failed')

    def test_receipt_written_before_even_an_unexpected_parser_failure(self):
        with patch('revision_receipt.failure_messages',side_effect=TypeError('synthetic parser failure')):
            result,writes=self.capture('failed',None)
        self.assertEqual(writes[0][1]['status'],'failed')
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['logDiagnostics'],'unavailable')

    def test_diagnostics_are_bounded(self):
        messages=failure_messages([{'output':'error '+'x'*3000} for _ in range(300)])
        self.assertEqual(len(messages),8)
        self.assertTrue(all(len(x)==2000 for x in messages))
        self.assertEqual(failure_messages('x'*131073),[])

    def test_mismatched_receipt_saved_but_not_accepted(self):
        writes=[]
        with self.assertRaises(ValueError):
            record_terminal('expected',{'deployment_uuid':'other','status':'finished'},lambda n,v:writes.append(v))
        self.assertEqual(writes[0]['deployment_uuid'],'expected')
        self.assertEqual(writes[0]['reportedDeploymentUuid'],'other')

    def test_missing_reported_uuid_keeps_exact_dispatch_uuid(self):
        writes=[]
        result=record_terminal('expected',{'status':'failed','logs':None},lambda n,v:writes.append(v))
        self.assertEqual(result['deployment_uuid'],'expected')
        self.assertIsNone(result['reportedDeploymentUuid'])

    def test_persistence_failure_is_not_suppressed(self):
        def failed_write(n,v):raise OSError('synthetic disk failure')
        with self.assertRaises(OSError):record_terminal('expected',{'status':'failed'},failed_write)
