"""One-request Throwable observer for the disposable private Compose fixture."""
import base64
from enum import StrEnum
import hashlib
import json
import pathlib
import re
import secrets
import subprocess
import time
import urllib.request

from private_collect import capture


INDEX = '/var/www/html/public/index.php'
INDEX_SHA256 = 'c96ed6bbe80f9105534af4d1510dc79f0143e6843970dba7ddd4ec7d03097cab'
IMAGE_ID = 'sha256:457b7b700395c0834edb3167a22f3701df440ea8b107293e562aac009fd249b3'
PROVIDER_SOURCE_SHA = '378ce3735c4522ebb6b68e93b909b0511f278763'
IMAGE_ID_PATTERN = r'sha256:[0-9a-f]{64}'
ANCHOR = b"$app = require_once __DIR__.'/../bootstrap/app.php';\n"
OBSERVER = '/tmp/vn-private-throwable-observer.php'
RECEIPT = '/tmp/vn-private-throwable-receipt.json'
ARMED = '/tmp/vn-private-throwable-armed.json'
READY = '/tmp/vn-private-throwable-fpm-ready.json'
DIAGNOSTIC_HEADER = 'X-VibeNest-Fixture-Diagnostic'
HERE = pathlib.Path(__file__).resolve().parent
EXPECTED_FPM = {'fpm': True, 'opcacheEnabled': True, 'timestampValidation': True, 'revalidateSeconds': 2,
                'fileCacheDisabled': True, 'preloadDisabled': True, 'workerReuseConfigured': True}


class InstallStage(StrEnum):
    IMAGE_INSPECT = 'image-inspect'
    ORIGINAL_INDEX = 'original-index'
    OBSERVER_WRITE = 'observer-write'
    OBSERVER_CHMOD = 'observer-chmod'
    OBSERVER_LINT = 'observer-lint'
    INDEX_WRITE = 'index-write'
    INDEX_LINT = 'index-lint'
    INDEX_HASH = 'index-hash'


class InstallReason(StrEnum):
    COMMAND_FAILED = 'stage-command-failed'
    INVALID_DIGEST = 'invalid-digest'
    IDENTITY_MISMATCH = 'identity-mismatch'
    INDEX_ANCHOR_MISMATCH = 'index-anchor-mismatch'


class ObserverInstallFailure(RuntimeError):
    def __init__(self, stage, reason, proof=None):
        super().__init__('Disposable Throwable observer could not be installed')
        self.stage = stage
        self.reason = reason
        self.evidence = {'observation': 'typed-install-failed', 'stage': stage, 'reason': reason, **(proof or {})}


def provider_artifact_evidence(path):
    try:
        with path.open('rb') as source:
            raw = source.read(4097)
        if len(raw) > 4096:
            return {'observation': 'provider-artifact-invalid'}
        payload = json.loads(raw)
    except OSError:
        return {'observation': 'provider-artifact-unavailable'}
    except ValueError:
        return {'observation': 'provider-artifact-invalid'}
    if not isinstance(payload, dict) or payload.get('requestedVersion') != '4.7.5' or payload.get('composeSourceSha') != PROVIDER_SOURCE_SHA:
        return {'observation': 'provider-artifact-invalid'}
    image_id, repo_digests = payload.get('imageId'), payload.get('repoDigests')
    if (not isinstance(image_id, str) or not re.fullmatch(IMAGE_ID_PATTERN, image_id) or
            not isinstance(repo_digests, list) or len(repo_digests) > 8 or any(
                not isinstance(digest, str) or not re.fullmatch(r'ghcr\.io/coollabsio/coolify@'+IMAGE_ID_PATTERN, digest)
                for digest in repo_digests)):
        return {'observation': 'provider-artifact-invalid'}
    return {'observation': 'provider-artifact-validated', 'requestedVersion': '4.7.5',
            'composeSourceSha': PROVIDER_SOURCE_SHA, 'imageId': image_id, 'repoDigests': repo_digests}


def write_provider_file(path, contents):
    proc = subprocess.run(['docker', 'exec', '--user', '0', '-i', 'coolify', 'tee', path],
                          input=contents, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    if proc.returncode:
        raise RuntimeError('Disposable Throwable observer write failed')


def observed_index(original, manifest, correlation):
    if hashlib.sha256(original).hexdigest() != INDEX_SHA256:
        raise ObserverInstallFailure(InstallStage.ORIGINAL_INDEX, InstallReason.IDENTITY_MISMATCH)
    if original.count(ANCHOR) != 1:
        raise ObserverInstallFailure(InstallStage.ORIGINAL_INDEX, InstallReason.INDEX_ANCHOR_MISMATCH)
    encoded_manifest = base64.b64encode(json.dumps(manifest, separators=(',', ':')).encode()).decode()
    hook = (f"require '{OBSERVER}';\n"
            f"vn_private_observe_throwable($app, json_decode(base64_decode('{encoded_manifest}'), true), "
            f"'{correlation}', '{RECEIPT}', '{ARMED}', '{READY}');\n")
    return original.replace(ANCHOR, ANCHOR+hook.encode(), 1)


class TypedCreateObserver:
    def __init__(self):
        self.nonce = secrets.token_hex(32)
        self.correlation = hashlib.sha256(self.nonce.encode()).hexdigest()
        self.manifest = json.loads((HERE/'private-throwable-manifest.json').read_text(encoding='utf-8'))

    def install(self):
        proof = {'expectedImageId': IMAGE_ID, 'expectedOriginalIndexSha256': INDEX_SHA256}
        stage = InstallStage.IMAGE_INSPECT
        try:
            image_id = capture(['docker', 'inspect', 'coolify', '--format', '{{.Image}}'], timeout=10, limit=256).strip()
            if not re.fullmatch(IMAGE_ID_PATTERN.encode(), image_id):
                raise ObserverInstallFailure(stage, InstallReason.INVALID_DIGEST)
            proof['imageId'] = image_id.decode('ascii')
            if proof['imageId'] != IMAGE_ID:
                raise ObserverInstallFailure(stage, InstallReason.IDENTITY_MISMATCH)

            stage = InstallStage.ORIGINAL_INDEX
            original = capture(['docker', 'exec', 'coolify', 'cat', INDEX], timeout=10, limit=8192)
            proof['originalIndexSha256'] = hashlib.sha256(original).hexdigest()
            patched = observed_index(original, self.manifest, self.correlation)
            proof['expectedPatchedIndexSha256'] = hashlib.sha256(patched).hexdigest()

            stage = InstallStage.OBSERVER_WRITE
            write_provider_file(OBSERVER, (HERE/'private-throwable.php').read_bytes())
            stage = InstallStage.OBSERVER_CHMOD
            capture(['docker', 'exec', '--user', '0', 'coolify', 'chmod', '0444', OBSERVER], timeout=10, limit=2048)
            stage = InstallStage.OBSERVER_LINT
            capture(['docker', 'exec', 'coolify', 'php', '-l', OBSERVER], timeout=10, limit=2048)
            proof['observerLint'] = 'passed'
            stage = InstallStage.INDEX_WRITE
            write_provider_file(INDEX, patched)
            stage = InstallStage.INDEX_LINT
            capture(['docker', 'exec', 'coolify', 'php', '-l', INDEX], timeout=10, limit=2048)
            proof['indexLint'] = 'passed'
            stage = InstallStage.INDEX_HASH
            actual = capture(['docker', 'exec', 'coolify', 'sha256sum', INDEX], timeout=10, limit=2048).split(maxsplit=1)
            if not actual or not re.fullmatch(rb'[0-9a-f]{64}', actual[0]):
                raise ObserverInstallFailure(stage, InstallReason.INVALID_DIGEST)
            proof['patchedIndexSha256'] = actual[0].decode('ascii')
            if proof['patchedIndexSha256'] != proof['expectedPatchedIndexSha256']:
                raise ObserverInstallFailure(stage, InstallReason.IDENTITY_MISMATCH)
        except ObserverInstallFailure as error:
            raise ObserverInstallFailure(error.stage, error.reason, proof) from None
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            if stage == InstallStage.OBSERVER_LINT:
                proof['observerLint'] = 'unavailable'
            if stage == InstallStage.INDEX_LINT:
                proof['indexLint'] = 'unavailable'
            raise ObserverInstallFailure(stage, InstallReason.COMMAND_FAILED, proof) from None
        return {'observation': 'typed-install-verified', **proof}

    def await_fpm(self):
        expected = EXPECTED_FPM | {'correlation': self.correlation}
        request = urllib.request.Request('http://127.0.0.1:8000/api/health', headers={DIAGNOSTIC_HEADER: self.nonce})
        deadline = time.monotonic()+12
        remaining = deadline-time.monotonic()
        while remaining > 0:
            try:
                with urllib.request.urlopen(request, timeout=min(2, remaining)) as response:
                    healthy = response.status == 200
            except OSError:
                healthy = False
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                break
            marker = self.read_file(READY, timeout=min(2, remaining))
            if marker is not None:
                if marker != expected or any(type(marker[key]) is not type(value) for key, value in expected.items()):
                    return {'observation': 'typed-fpm-config-mismatch'}
                if healthy:
                    return {'observation': 'patched-fpm-ready', **EXPECTED_FPM}
            remaining = deadline-time.monotonic()
            time.sleep(max(0, min(1, remaining)))
            remaining = deadline-time.monotonic()
        return {'observation': 'typed-fpm-not-observed'}

    def read_file(self, path, *, timeout=10):
        try:
            raw = capture(['docker', 'exec', '--user', '0', 'coolify', 'head', '-c', '2049', path],
                          timeout=timeout, limit=2048)
            return json.loads(raw)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
            return None

    def read(self):
        if self.read_file(ARMED) != {'correlation': self.correlation}:
            return {'observation': 'typed-observer-not-armed'}
        metadata = self.read_file(RECEIPT)
        if metadata is None:
            return {'observation': 'typed-no-throwable'}
        if (not isinstance(metadata, dict) or metadata.get('correlation') != self.correlation or
                metadata.get('observation') != 'observed'):
            return {'observation': 'typed-receipt-invalid'}
        result = {'observation': 'typed-observed'}
        exception_class = metadata.get('exceptionClass')
        if exception_class in self.manifest['classes']:
            result['exceptionClass'] = exception_class
        else:
            result['classStatus'] = 'unknown'
        file, line = metadata.get('providerFile'), metadata.get('providerLine')
        if file in self.manifest['files'] and type(line) is int and 0 < line <= 99999:
            result.update(providerFile=file, providerLine=line)
        else:
            result['fileStatus'] = 'unknown'
        code = metadata.get('exceptionCode')
        if type(code) in (int, str) and str(code) in self.manifest['codes']:
            result['exceptionCode'] = code
        else:
            result['codeStatus'] = 'unknown'
        return result
