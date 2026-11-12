import hashlib
import itertools
import os
import unittest
from unittest.mock import Mock, patch

from private_native import NativeFixture
from private_throwable import ANCHOR, DIAGNOSTIC_HEADER, EXPECTED_FPM, READY, TypedCreateObserver, observed_index


class TypedCreateObserverTests(unittest.TestCase):
    def test_index_hook_requires_exact_original_identity_and_one_anchor(self):
        original = b'<?php\n'+ANCHOR+b'$kernel->handle($request);\n'
        expected = hashlib.sha256(original).hexdigest()
        with patch('private_throwable.INDEX_SHA256', expected):
            patched = observed_index(original, {'classes': ['Exception']}, 'a'*64)
            self.assertTrue(patched.startswith(b'<?php\n'+ANCHOR))
            self.assertTrue(patched.endswith(b'$kernel->handle($request);\n'))
            self.assertEqual(patched.count(b'vn_private_observe_throwable'), 1)
            with self.assertRaises(RuntimeError):
                observed_index(original+b'//unexpected\n', {}, 'a'*64)

    def test_receipt_checks_correlation_and_exports_only_known_typed_values(self):
        observer = TypedCreateObserver()
        armed = {'correlation': observer.correlation}
        receipt = armed | {
            'observation': 'observed', 'exceptionClass': 'Exception',
            'providerFile': 'app/Models/Application.php', 'providerLine': 59,
            'exceptionCode': 0, 'message': 'synthetic-secret', 'trace': 'synthetic-secret',
        }
        with patch.object(observer, 'read_file', side_effect=(armed, receipt)):
            self.assertEqual(observer.read(), {'observation': 'typed-observed', 'exceptionClass': 'Exception',
                                               'providerFile': 'app/Models/Application.php', 'providerLine': 59,
                                               'exceptionCode': 0})
        with patch.object(observer, 'read_file', side_effect=(armed, receipt | {'correlation': 'other'})):
            self.assertEqual(observer.read(), {'observation': 'typed-receipt-invalid'})

    def test_unknown_class_file_and_code_cannot_export_provider_strings(self):
        observer = TypedCreateObserver()
        armed = {'correlation': observer.correlation}
        receipt = armed | {
            'observation': 'observed', 'exceptionClass': 'Secret\\Unexpected',
            'providerFile': '/secret/path.php', 'providerLine': 17, 'exceptionCode': 'secret-code',
        }
        with patch.object(observer, 'read_file', side_effect=(armed, receipt)):
            self.assertEqual(observer.read(), {'observation': 'typed-observed', 'classStatus': 'unknown',
                                               'fileStatus': 'unknown', 'codeStatus': 'unknown'})

    def test_distinguishes_unarmed_request_from_armed_request_without_throwable(self):
        observer = TypedCreateObserver()
        with patch.object(observer, 'read_file', return_value=None):
            self.assertEqual(observer.read(), {'observation': 'typed-observer-not-armed'})
        with patch.object(observer, 'read_file', side_effect=({'correlation': observer.correlation}, None)):
            self.assertEqual(observer.read(), {'observation': 'typed-no-throwable'})

    def test_fpm_readiness_requires_normal_health_and_exact_correlated_marker(self):
        observer = TypedCreateObserver()
        expected = EXPECTED_FPM | {'correlation': observer.correlation}
        for marker, status in ((expected, 'patched-fpm-ready'), (expected | {'timestampValidation': 1}, 'typed-fpm-config-mismatch'),
                               (expected | {'correlation': 'other'}, 'typed-fpm-config-mismatch')):
            with self.subTest(status=status), patch.object(observer, 'read_file', return_value=marker) as read, patch('private_throwable.urllib.request.urlopen') as get:
                get.return_value.__enter__.return_value.status = 200
                result = observer.await_fpm()
                self.assertEqual(result['observation'], status)
                self.assertNotIn('correlation', result)
                self.assertEqual(read.call_args.args, (READY,))
                request = get.call_args.args[0]
                self.assertEqual((request.get_method(), request.full_url), ('GET', 'http://127.0.0.1:8000/api/health'))
                self.assertEqual({key.lower(): value for key, value in request.headers.items()}, {DIAGNOSTIC_HEADER.lower(): observer.nonce})

    def test_fpm_wait_is_bounded_and_missing_marker_cannot_pass(self):
        observer = TypedCreateObserver()
        with patch.object(observer, 'read_file', return_value=None), patch('private_throwable.urllib.request.urlopen') as get, patch('private_throwable.time.monotonic', side_effect=itertools.count()), patch('private_throwable.time.sleep'):
            get.return_value.__enter__.return_value.status = 200
            self.assertEqual(observer.await_fpm(), {'observation': 'typed-fpm-not-observed'})
            self.assertGreater(get.call_count, 0)
            self.assertLess(get.call_count, 12)

    def test_unverified_fpm_aborts_before_the_provider_create_post(self):
        fixture = Mock()
        fixture.result = {'currentStage': 'provider-first-application-create'}
        fixture.token = 'synthetic'
        for observation in ('typed-fpm-not-observed', 'typed-fpm-config-mismatch'):
            with self.subTest(observation=observation), patch.dict(os.environ, {'VN_PRIVATE_TYPED_DIAGNOSTIC':'1'}), patch('private_native.TypedCreateObserver') as observer, patch('private_native.urllib.request.urlopen') as request:
                observer.return_value.await_fpm.return_value = {'observation': observation}
                with self.assertRaisesRegex(RuntimeError, 'patched FPM entrypoint was not verified'):
                    NativeFixture.api(fixture, '/applications/public', 'POST', {})
                request.assert_not_called()
