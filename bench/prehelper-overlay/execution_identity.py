"""Read-only identity gate for a newly packaged, explicitly reviewed fixture SHA.

No environment overrides, checkout, fetch, build or dispatch. Review JSON is an
external coordinator artifact produced AFTER committing the execution package;
its digest is a separately approved workflow input, never derived by this gate.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASE_SHA = 'f930ef88d4cdb0c4645ea38a67ad080dc7f78c4c'
OVERLAY_PATHS = {
    'bench/prehelper-overlay/execution_identity.py',
    'bench/prehelper-overlay/prehelper_contract.py',
    'bench/prehelper-overlay/prehelper_probe.php',
    'bench/prehelper-overlay/CONTRACT.txt',
    '.github/workflows/prehelper-contract.yml',
}


def _git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=15).stdout


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate review field')
        result[key] = value
    return result


def _tree(root, revision):
    result = {}
    for row in _git(root, 'ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        path = name.decode('utf-8')
        if (kind != 'blob' or mode not in ('100644', '100755')
                or path.startswith('/') or '..' in path.split('/') or '\\' in path):
            raise ValueError('Unsupported execution tree')
        result[path] = (mode, oid)
    return result


def verify_execution(review_path, approved_review_sha256):
    if (os.name != 'posix' or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('VN_PRIVATE_DISPOSABLE') != '1'
            or os.environ.get('GITHUB_REPOSITORY') != 'NikitaBabenko/vibenest-compose-contract-fixture'
            or any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY'))):
        raise ValueError('Disposable fixture execution required')
    if not re.fullmatch('[0-9a-f]{64}', approved_review_sha256):
        raise ValueError('Approved review digest required')
    with Path(review_path).open('rb') as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576 or hashlib.sha256(raw).hexdigest() != approved_review_sha256:
        raise ValueError('Execution review mismatch')
    review = json.loads(raw, object_pairs_hook=_object)
    if (set(review) != {'schemaVersion', 'fixtureBaseSha', 'executionSha', 'coreFiles', 'overlayFiles', 'overlayDigest'}
            or type(review['schemaVersion']) is not int or review['schemaVersion'] != 1
            or review['fixtureBaseSha'] != BASE_SHA
            or not re.fullmatch('[0-9a-f]{40}', review['executionSha'])):
        raise ValueError('Unsupported execution review')
    execution = review['executionSha']
    root = Path(_git(Path.cwd(), 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    if (execution == BASE_SHA or _git(root, 'rev-parse', 'HEAD').decode().strip() != execution
            or os.environ.get('GITHUB_SHA') != execution
            or os.environ.get('VN_PRIVATE_REVIEWED_SHA') != execution):
        raise ValueError('Actual execution SHA differs from reviewed SHA')
    _git(root, 'merge-base', '--is-ancestor', BASE_SHA, execution)
    base, current = _tree(root, BASE_SHA), _tree(root, execution)
    if (set(review['coreFiles']) != set(base) or set(review['overlayFiles']) != OVERLAY_PATHS
            or set(current) != set(base) | OVERLAY_PATHS or set(base) & OVERLAY_PATHS):
        raise ValueError('Execution package file set differs from review')
    for path, entry in base.items():
        if current[path] != entry:
            raise ValueError('Reviewed fixture core changed')
    for group in ('coreFiles', 'overlayFiles'):
        for path, expected in review[group].items():
            if (set(expected) != {'mode', 'sha256'} or expected['mode'] != current[path][0]
                    or not re.fullmatch('[0-9a-f]{64}', expected['sha256'])):
                raise ValueError('Invalid reviewed file identity')
            committed = _git(root, 'show', execution + ':' + path)
            file = root / path
            if (any(part.is_symlink() for part in (file, *file.parents)) or not file.is_file()
                    or hashlib.sha256(committed).hexdigest() != expected['sha256']
                    or file.read_bytes() != committed
                    or bool(file.stat().st_mode & 0o111) != (expected['mode'] == '100755')):
                raise ValueError('Execution bytes differ from reviewed file')
    digest = hashlib.sha256(json.dumps(review['overlayFiles'], sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    if digest != review['overlayDigest']:
        raise ValueError('Overlay digest mismatch')
    if Path(__file__).resolve() != root / 'bench/prehelper-overlay/execution_identity.py':
        raise ValueError('Identity gate loaded outside reviewed execution package')
    return {'fixtureBaseSha': BASE_SHA, 'executionSha': execution,
            'overlayDigest': digest, 'executionReviewDigest': approved_review_sha256}
