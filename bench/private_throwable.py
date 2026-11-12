"""One-request Throwable observer for the disposable private Compose fixture."""
import base64
import hashlib
import json
import pathlib
import secrets
import subprocess
import time
import urllib.request

from private_collect import capture


INDEX = '/var/www/html/public/index.php'
INDEX_SHA256 = 'c96ed6bbe80f9105534af4d1510dc79f0143e6843970dba7ddd4ec7d03097cab'
IMAGE_ID = 'sha256:457b7b700395c0834edb3167a22f3701df440ea8b107293e562aac009fd249b3'
ANCHOR = b"$app = require_once __DIR__.'/../bootstrap/app.php';\n"
OBSERVER = '/tmp/vn-private-throwable-observer.php'
RECEIPT = '/tmp/vn-private-throwable-receipt.json'
ARMED = '/tmp/vn-private-throwable-armed.json'
READY = '/tmp/vn-private-throwable-fpm-ready.json'
DIAGNOSTIC_HEADER = 'X-VibeNest-Fixture-Diagnostic'
HERE = pathlib.Path(__file__).resolve().parent
EXPECTED_FPM = {'fpm': True, 'opcacheEnabled': True, 'timestampValidation': True, 'revalidateSeconds': 2,
                'fileCacheDisabled': True, 'preloadDisabled': True, 'workerReuseConfigured': True}


def write_provider_file(path, contents):
    proc = subprocess.run(['docker', 'exec', '--user', '0', '-i', 'coolify', 'tee', path],
                          input=contents, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    if proc.returncode:
        raise RuntimeError('Disposable Throwable observer write failed')


def observed_index(original, manifest, correlation):
    if hashlib.sha256(original).hexdigest() != INDEX_SHA256 or original.count(ANCHOR) != 1:
        raise RuntimeError('Disposable Coolify entrypoint identity mismatch')
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
        image_id = capture(['docker', 'inspect', 'coolify', '--format', '{{.Image}}'], timeout=10, limit=256)
        if image_id.decode().strip() != IMAGE_ID:
            raise RuntimeError('Disposable Coolify image identity mismatch')
        original = capture(['docker', 'exec', 'coolify', 'cat', INDEX], timeout=10, limit=8192)
        patched = observed_index(original, self.manifest, self.correlation)
        write_provider_file(OBSERVER, (HERE/'private-throwable.php').read_bytes())
        capture(['docker', 'exec', '--user', '0', 'coolify', 'chmod', '0444', OBSERVER], timeout=10, limit=2048)
        capture(['docker', 'exec', 'coolify', 'php', '-l', OBSERVER], timeout=10, limit=2048)
        write_provider_file(INDEX, patched)
        capture(['docker', 'exec', 'coolify', 'php', '-l', INDEX], timeout=10, limit=2048)
        actual = capture(['docker', 'exec', 'coolify', 'sha256sum', INDEX], timeout=10, limit=2048).split()[0]
        if actual.decode() != hashlib.sha256(patched).hexdigest():
            raise RuntimeError('Disposable Throwable observer identity mismatch')

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
