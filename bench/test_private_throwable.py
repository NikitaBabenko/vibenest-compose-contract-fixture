import hashlib
import itertools
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

from private_native import NativeFixture
from private_throwable import (
    ANCHOR, DIAGNOSTIC_HEADER, EXPECTED_FPM, IMAGE_ID, PROVIDER_SOURCE_SHA, READY,
    InstallReason, InstallStage, TypedCreateObserver, observed_index, provider_artifact_evidence,
)


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

    def run_failed_install(self, original, responses, writes, stage, reason, index_sha=None):
        fixture = Mock()
        fixture.result = {'currentStage': 'provider-first-application-create'}
        fixture.token = 'synthetic'
        expected_index = index_sha or hashlib.sha256(original).hexdigest()
        with patch.dict(os.environ, {'VN_PRIVATE_TYPED_DIAGNOSTIC': '1'}), \
             patch('private_throwable.INDEX_SHA256', expected_index), \
             patch('private_throwable.capture', side_effect=responses), \
             patch('private_throwable.write_provider_file', side_effect=writes), \
             patch('private_native.urllib.request.urlopen') as request:
            with self.assertRaisesRegex(RuntimeError, 'observer could not be installed'):
                NativeFixture.api(fixture, '/applications/public', 'POST', {})
            request.assert_not_called()
        name, evidence = fixture.save.call_args.args
        self.assertEqual(name, 'provider-create-exception')
        self.assertEqual((evidence['observation'], evidence['stage'], evidence['reason']), ('typed-install-failed', stage, reason))
        self.assertNotIn('synthetic-private-error', json.dumps(evidence))
        return evidence

    def test_each_install_command_failure_records_its_stage_and_skips_post(self):
        original = b'<?php\n'+ANCHOR
        capture_stages = (InstallStage.IMAGE_INSPECT, InstallStage.ORIGINAL_INDEX, InstallStage.OBSERVER_CHMOD,
                          InstallStage.OBSERVER_LINT, InstallStage.INDEX_LINT, InstallStage.INDEX_HASH)
        responses = [IMAGE_ID.encode(), original, b'', b'', b'', b'']
        for index, stage in enumerate(capture_stages):
            with self.subTest(stage=stage):
                mutated = responses.copy()
                mutated[index] = RuntimeError('synthetic-private-error')
                evidence = self.run_failed_install(original, mutated, [None, None], stage, InstallReason.COMMAND_FAILED)
                if stage == InstallStage.OBSERVER_LINT:
                    self.assertEqual(evidence['observerLint'], 'unavailable')
                if stage == InstallStage.INDEX_LINT:
                    self.assertEqual(evidence['indexLint'], 'unavailable')
        for index, stage in enumerate((InstallStage.OBSERVER_WRITE, InstallStage.INDEX_WRITE)):
            with self.subTest(stage=stage):
                writes = [None, None]
                writes[index] = OSError('synthetic-private-error')
                self.run_failed_install(original, responses, writes, stage, InstallReason.COMMAND_FAILED)

    def test_identity_failure_reports_only_validated_hashes_and_skips_post(self):
        original = b'<?php\n'+ANCHOR
        responses = [IMAGE_ID.encode(), original, b'', b'', b'', b'']
        bad_image = self.run_failed_install(original, [b'synthetic-private-error'], [], InstallStage.IMAGE_INSPECT,
                                            InstallReason.INVALID_DIGEST)
        self.assertNotIn('imageId', bad_image)
        unexpected_image = 'sha256:'+'c'*64
        evidence = self.run_failed_install(original, [unexpected_image.encode()], [], InstallStage.IMAGE_INSPECT,
                                           InstallReason.IDENTITY_MISMATCH)
        self.assertEqual(evidence['imageId'], unexpected_image)
        evidence = self.run_failed_install(original, responses, [None, None], InstallStage.ORIGINAL_INDEX,
                                           InstallReason.IDENTITY_MISMATCH, index_sha='a'*64)
        self.assertEqual(evidence['originalIndexSha256'], hashlib.sha256(original).hexdigest())
        missing_anchor = b'<?php\n'
        self.run_failed_install(missing_anchor, [IMAGE_ID.encode(), missing_anchor], [], InstallStage.ORIGINAL_INDEX,
                                InstallReason.INDEX_ANCHOR_MISMATCH)
        self.run_failed_install(original, responses, [None, None], InstallStage.INDEX_HASH, InstallReason.INVALID_DIGEST)
        evidence = self.run_failed_install(original, responses[:-1]+[b'c'*64+b'  index.php'], [None, None],
                                           InstallStage.INDEX_HASH, InstallReason.IDENTITY_MISMATCH)
        self.assertEqual(evidence['patchedIndexSha256'], 'c'*64)
        self.assertEqual(evidence['indexLint'], 'passed')

    def test_bootstrap_artifact_projects_only_pinned_validated_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp)/'provider-artifact.json'
            self.assertEqual(provider_artifact_evidence(path), {'observation': 'provider-artifact-unavailable'})
            digest = 'ghcr.io/coollabsio/coolify@sha256:'+'a'*64
            safe = {'requestedVersion': '4.7.5', 'composeSourceSha': PROVIDER_SOURCE_SHA, 'imageId': IMAGE_ID,
                    'repoDigests': [digest]}
            path.write_text(json.dumps(safe | {'env': 'synthetic-private-error'}), encoding='utf-8')
            self.assertEqual(provider_artifact_evidence(path), {'observation': 'provider-artifact-validated', **safe})
            for invalid in (safe | {'repoDigests': ['other/image@sha256:'+'a'*64]},
                            safe | {'imageId': 'synthetic-private-error'}, safe | {'composeSourceSha': 'b'*40}):
                path.write_text(json.dumps(invalid), encoding='utf-8')
                self.assertEqual(provider_artifact_evidence(path), {'observation': 'provider-artifact-invalid'})
            path.write_bytes(b'a'*4097)
            self.assertEqual(provider_artifact_evidence(path), {'observation': 'provider-artifact-invalid'})
