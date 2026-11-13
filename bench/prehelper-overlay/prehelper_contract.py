"""Unrun overlay for unchanged f930 core at a NEW reviewed execution SHA.

Call run_contract(fixture, fresh_app_uuid) only inside an explicitly allocated
disposable fixture session, before any capability issuance or native dispatch.
Reuses fixture.php(), fixture.save(), and its existing provider container.
Does not use SSH, create channels, edit repositories, or call fixture.deploy().
"""
import base64
import copy
import json
from pathlib import Path
from execution_identity import verify_execution

CAPABILITY_KEY = 'VN_ARTIFACT_CAPABILITY'


def cases():
    # No mounts, builds, commands, domains or lifecycle operations are executed.
    baseline = {'services': {'web': {'image': 'alpine:3.21'}}}
    yield 'baseline', baseline, False
    for name, patch, exposure in [
        ('empty-reserved-environment', {'environment': {CAPABILITY_KEY: ''}}, True),
        ('empty-reserved-build-arg', {'build': {'context': '.', 'args': {CAPABILITY_KEY: ''}}}, True),
        ('direct-reference', {'environment': {'PROBE': '${VN_ARTIFACT_CAPABILITY}'}}, None),
        ('default-reference', {'environment': {'PROBE': '${VN_ARTIFACT_CAPABILITY:-fallback}'}}, None),
        ('required-reference', {'environment': {'PROBE': '${VN_ARTIFACT_CAPABILITY:?synthetic-required}'}}, None),
        ('label-reference', {'labels': {'probe.value': '${VN_ARTIFACT_CAPABILITY}'}}, None),
        ('command-reference', {'command': ['echo', '${VN_ARTIFACT_CAPABILITY}']}, None),
        ('healthcheck-reference', {'healthcheck': {'test': ['CMD', 'echo', '${VN_ARTIFACT_CAPABILITY}']}}, None),
        ('build-arg-reference', {'build': {'context': '.', 'args': {'PROBE': '${VN_ARTIFACT_CAPABILITY}'}}}, None),
        ('literal-dollar-reference', {'environment': {'PROBE': '$${VN_ARTIFACT_CAPABILITY}'}}, None),
        ('required-error-reference', {'environment': {'PROBE': '${VN_MISSING:?${VN_ARTIFACT_CAPABILITY}}'}}, None),
    ]:
        document = copy.deepcopy(baseline)
        document['services']['web'].update(patch)
        yield name, document, exposure


def run_contract(fixture, fresh_app_uuid, review_path, approved_review_sha256):
    identity = verify_execution(review_path, approved_review_sha256)
    if fixture.sha != identity['executionSha']:
        raise RuntimeError('Fixture instance does not match reviewed execution')
    if Path(__file__).resolve().parent != Path.cwd().resolve() / 'bench/prehelper-overlay':
        raise RuntimeError('Overlay loaded outside reviewed fixture root')
    if fresh_app_uuid not in fixture.apps:
        raise RuntimeError('Fresh application must belong to the fixture')
    # These bytes contain a public synthetic test only. No actual bearer is read.
    source = Path(__file__).with_name('prehelper_probe.php').read_text(encoding='utf-8').encode('utf-8')
    if not source.startswith(b'<?php\n'):
        raise RuntimeError('Unexpected probe source')
    script = base64.b64encode(source[len(b'<?php\n'):]).decode('ascii')
    results = []
    failures = []
    for name, compose, expected_exposure in cases():
        request = {**identity, 'acknowledgement': 'DISPOSABLE_SYNTHETIC_ONLY',
                   'application': fresh_app_uuid, 'case': name, 'compose': compose,
                   'buildCommand': fixture.build_command}
        encoded = base64.b64encode(json.dumps(request, separators=(',', ':')).encode()).decode('ascii')
        # fixture.php bootstraps the real pinned provider. No shell source/env interpolation.
        result = json.loads(fixture.php(
            f'$vnRequest=json_decode(base64_decode("{encoded}"),true,512,JSON_THROW_ON_ERROR);'
            f'eval(base64_decode("{script}"));'))
        results.append(result)
        if result.get('status') != 'observed':
            failures.append(name + ': probe-refused-or-unavailable')
            continue
        if result.get('channelAccepted') is not False or result.get('commandUnchanged') is not True:
            failures.append(name + ': command-or-acceptance-contract')
        if result.get('commandContainsSyntheticCapability') or result.get('generatedBuildArgsContainValue'):
            failures.append(name + ': command-value-exposure')
        if expected_exposure is not None:
            observed = result['surfaces']['parser-persisted-compose']['containsSyntheticCapability']
            if observed is not expected_exposure:
                failures.append(name + ': pinned-parser-exposure-expectation')
    summary = {'schemaVersion': 1, **identity,
               'providerSha': '378ce3735c4522ebb6b68e93b909b0511f278763',
               'channelAccepted': False, 'productionEnablementAllowed': False,
               'nativeDeploymentDispatched': False,
               'classification': 'diagnostic-contract-only', 'results': results,
               'contractFailures': failures,
               'coverageLimit': 'Real Parser5 and command transforms; no native job, log or CLI execution.'}
    fixture.save('prehelper-adversarial-contract', summary)
    if failures:
        raise RuntimeError('Pre-helper contract incomplete; consult fixed-code receipt')
    return summary
