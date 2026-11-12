import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from private_collect import (
    QUEUE_LOG_LIMIT, classify_native_queue_log, exact_native_queue_evidence,
    provider_create_exception, provider_exception_metadata, verify_missing_refusal,
)


class MissingRefusalTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(project='project', application='app', attempt='attempt', deployment='deployment',
                          generation=1, sourceSha='a'*40, helperDigest='b'*64, settingsDigest='c'*64)
        self.names = ['vnprivate1-redis', 'baseline']
        self.name = 'vnprivate11-web'
        self.receipt = dict(schema=1, scope=copy.deepcopy(self.scope), stage='retained-volume-inspection',
                            code='assigned-volume-missing', createIssued=False,
                            volumeNameDigest=hashlib.sha256(self.name.encode()).hexdigest(),
                            inventoryDigest=hashlib.sha256(json.dumps(sorted(self.names), separators=(',', ':')).encode()).hexdigest())

    def verify(self, receipt, **kwargs):
        args = dict(scope=self.scope, expected_name=self.name, inventory=self.names, complete=True)
        return verify_missing_refusal(receipt, **(args | kwargs))

    def test_exact_cause_and_independent_inventory(self):
        self.assertEqual(self.verify(self.receipt), self.receipt)
        self.assertNotIn(self.name, json.dumps(self.verify(self.receipt)))
        self.assertEqual(self.verify(self.receipt, inventory=list(reversed(self.names))), self.receipt)

    def test_generic_or_wrong_stage_failure_cannot_pass(self):
        for receipt in [None, {}, {'status':'failed'}, self.receipt | {'stage':'source-verification'},
                        self.receipt | {'code':'source-mismatch'}, self.receipt | {'stage':'volume-list'},
                        self.receipt | {'createIssued':True}, self.receipt | {'createIssued':None},
                        self.receipt | {'createIssued':0}, self.receipt | {'schema':True},
                        self.receipt | {'volumeNameDigest':'d'*64}, self.receipt | {'inventoryDigest':'d'*64},
                        self.receipt | {'unexpected':'name'}]:
            with self.subTest(receipt=receipt), self.assertRaises(ValueError): self.verify(receipt)
        for key in self.receipt:
            receipt=copy.deepcopy(self.receipt); del receipt[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): self.verify(receipt)
        for key in self.scope:
            receipt=copy.deepcopy(self.receipt); receipt['scope'][key] = 2 if key == 'generation' else 'other'
            with self.subTest(scope=key), self.assertRaises(ValueError): self.verify(receipt)

    def test_unknown_or_conflicting_independent_inventory_refused(self):
        for kw in [dict(complete=False), dict(complete=None), dict(inventory=None),
                   dict(inventory=self.names+[self.name]), dict(inventory=self.names+self.names),
                   dict(inventory=['']), dict(inventory=['unexpected']), dict(expected_name='vnprivate12-web')]:
            with self.subTest(kw=kw), self.assertRaises(ValueError): self.verify(self.receipt, **kw)


class ProviderExceptionTests(unittest.TestCase):
    def log(self, exception, *, message='synthetic-secret-in-message'):
        context = json.dumps({'userId': 0, 'exception': exception}, separators=(',', ':'))
        return f'[2026-11-12 06:26:21] production.ERROR: {message} {context} []\n'.encode()

    def test_exports_only_known_metadata_from_exception_context(self):
        exception = (
            '[object] (Illuminate\\Database\\QueryException(code: 42703): '
            'SQLSTATE[42703] synthetic-secret-in-query)\n[stacktrace]\n'
            '#0 /var/www/html/app/Models/Application.php(417): synthetic-secret-in-stack()'
        )
        self.assertEqual(provider_exception_metadata(self.log(exception)), {
            'observation': 'classified', 'exceptionClass': 'Illuminate\\Database\\QueryException',
            'sqlState': '42703', 'providerFile': 'app/Models/Application.php', 'providerLine': 417,
        })

    def test_coolify_redaction_tap_normalizes_throwable_to_an_object(self):
        exception = {
            'class': 'Illuminate\\Database\\QueryException', 'code': 42703,
            'message': 'SQLSTATE[23505] synthetic-secret-in-query',
            'file': '/var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php', 'line': 826,
            'trace': '#0 /var/www/html/app/Http/Controllers/Api/ApplicationsController.php(1948): synthetic-secret()',
            'previous': {'class': 'PDOException', 'code': 'synthetic-secret', 'message': 'synthetic-secret'},
        }
        self.assertEqual(provider_exception_metadata(self.log(exception)), {
            'observation': 'classified', 'exceptionClass': 'Illuminate\\Database\\QueryException',
            'sqlState': '42703', 'providerFile': 'app/Http/Controllers/Api/ApplicationsController.php',
            'providerLine': 1948,
        })

    def test_coolify_redacted_object_does_not_export_untyped_metadata(self):
        exception = {
            'class': 'TypeError', 'code': 'synthetic-secret',
            'message': '#0 /var/www/html/app/Models/Application.php(617): fake()',
            'file': '/var/www/html/app/Models/Application.php', 'line': '617', 'trace': None,
        }
        self.assertEqual(provider_exception_metadata(self.log(exception)), {
            'observation': 'classified', 'exceptionClass': 'TypeError',
        })
        exception['line'] = 617
        self.assertEqual(provider_exception_metadata(self.log(exception)), {
            'observation': 'classified', 'exceptionClass': 'TypeError',
            'providerFile': 'app/Models/Application.php', 'providerLine': 617,
        })

    def test_refuses_false_frame_in_message_or_non_allowlisted_stack_path(self):
        fake_frame = '#0 /var/www/html/app/Models/Application.php(617): fake()'
        exception = (
            '[object] (TypeError(code: 0): ' + fake_frame + ')\n[stacktrace]\n'
            '#0 /var/www/html/app/Models/Unexpected.php(900): synthetic-secret-in-stack()'
        )
        self.assertEqual(provider_exception_metadata(self.log(exception, message=fake_frame)), {
            'observation': 'classified', 'exceptionClass': 'TypeError',
        })

    def test_missing_multiple_and_unrecognized_records_do_not_export_metadata(self):
        raw = self.log('[object] (Vendor\\SecretClass(code: 900): synthetic-secret)')
        for logs, status in ((b'', 'missing'), (raw+raw, 'ambiguous'), (raw, 'unclassified')):
            with self.subTest(status=status):
                self.assertEqual(provider_exception_metadata(logs), {'observation': status})

    def test_rotation_truncation_and_oversize_do_not_read_log(self):
        for before, after in (((1, 200), (2, 200)), ((1, 200), (1, 100)), ((1, 200), (1, 65737))):
            with self.subTest(before=before, after=after), patch('private_collect.provider_log_cursor', return_value=after), patch('private_collect.capture') as read:
                self.assertEqual(provider_create_exception(before), {'observation': 'rotated-or-over-limit'})
                read.assert_not_called()

    def test_reads_exact_append_and_refuses_cursor_change(self):
        raw = self.log('[object] (Error(code: 0): synthetic-secret)')
        before, after = (1, 200), (1, 200+len(raw))
        for verify, expected in ((after, {'observation': 'classified', 'exceptionClass': 'Error'}),
                                 ((2, after[1]), {'observation': 'cursor-changed'})):
            with self.subTest(verify=verify), patch('private_collect.provider_log_cursor', side_effect=(after, verify)), patch('private_collect.capture', return_value=raw) as read:
                self.assertEqual(provider_create_exception(before), expected)
                self.assertEqual(read.call_args.args[0][-2:], [str(before[1]), str(len(raw))])
                self.assertEqual(read.call_args.kwargs['limit'], 65536)


class NativeQueueEvidenceTests(unittest.TestCase):
    def log(self, *lines):
        return json.dumps([{'type':'stderr','output':line,'hidden':True,'command':'FIXTURE_REFUSAL loader-entry'}
                           for line in lines]).encode()

    def test_queue_log_exports_only_allowlisted_progress_refusal_and_tool_codes(self):
        raw=self.log('Preparing container with helper image: synthetic-private-reference',
                     'Pulling & building required images.', '/tmp/v: OK',
                     'FIXTURE_SCAN native-normalization '+'a'*64+' 123 leak=false',
                     'curl: (28) synthetic-private-endpoint', 'FIXTURE_REFUSAL loader-helper-delivery',
                     'FIXTURE_REFUSAL synthetic-private-code', 'curl: (99) synthetic-private-endpoint')
        self.assertEqual(classify_native_queue_log(raw,[]),{
            'observation':'known-refusal',
            'progressCodes':['helper-scan-native-normalization','launcher-hash-verified','provider-build','provider-helper-preparation'],
            'refusalCodes':['loader-helper-delivery'],'toolCodes':['curl-timeout'],
        })

    def test_queue_log_refuses_canary_or_oversize_and_marks_unknown_or_ambiguous(self):
        canary='f'*64
        self.assertEqual(classify_native_queue_log(self.log('FIXTURE_REFUSAL helper-manifest',canary),[canary]),
                         {'observation':'queue-log-leak-refused'})
        self.assertEqual(classify_native_queue_log(b'x'*(QUEUE_LOG_LIMIT+1),[]),{'observation':'queue-log-unavailable'})
        self.assertEqual(classify_native_queue_log(b'invalid',[]),{'observation':'queue-log-unrecognized'})
        unknown=classify_native_queue_log(self.log('unrecognized synthetic error'),[])
        self.assertEqual(unknown,{'observation':'unknown-refusal','progressCodes':[],'refusalCodes':[],'toolCodes':[]})
        ambiguous=classify_native_queue_log(self.log('FIXTURE_REFUSAL helper-source-verify','/tmp/v: FAILED'),[])
        self.assertEqual(ambiguous['observation'],'ambiguous-refusal')
        self.assertEqual(ambiguous['refusalCodes'],['helper-source-verify','launcher-hash-mismatch'])

    def test_exact_queue_read_checks_application_and_deployment_and_projects_terminal_status(self):
        meta=json.dumps({'status':'failed','commitMatches':True,'ignored':'synthetic-private-data'}).encode()
        raw=meta+b'\n'+self.log('FIXTURE_REFUSAL helper-settings-parse')
        with patch('private_collect.capture',return_value=raw) as read:
            receipt=exact_native_queue_evidence('testapp','testdeployment','a'*40,[])
            self.assertEqual(receipt,{'observation':'exact-queue-row','sourceCommitMatches':True,'queueStatus':'failed',
                                     'log':{'observation':'known-refusal','progressCodes':[],
                                            'refusalCodes':['helper-settings-parse'],'toolCodes':[]}})
            command=read.call_args.args[0][-1]
            self.assertIn("where('application_id',$a->id)->where('deployment_uuid','testdeployment')->sole()",command)
            self.assertEqual(read.call_args.kwargs['limit'],QUEUE_LOG_LIMIT+1024)
        with patch('private_collect.capture') as read:
            self.assertEqual(exact_native_queue_evidence("bad'",'testdeployment','a'*40,[]),
                             {'observation':'queue-scope-invalid'})
            read.assert_not_called()


if __name__ == '__main__': unittest.main()
