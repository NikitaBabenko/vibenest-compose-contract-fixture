"""Scan raw input before redaction. Export only fixed labels and content digests."""
import base64
import hashlib
import json
import re
import urllib.parse


def scan_canaries(raw, canaries, *, surface):
    if surface not in {'hidden-log', 'command', 'build-args', 'context', 'layer', 'runtime-env', 'error'}:
        raise ValueError('Unknown evidence surface')
    if isinstance(raw, str): raw = raw.encode()
    if not isinstance(raw, bytes): raise ValueError('Expected raw bytes')
    compact = re.sub(rb'\s+', b'', raw)
    categories = set()
    for canary in canaries:
        if isinstance(canary, str): canary = canary.encode()
        if not isinstance(canary, bytes) or len(canary) < 32:
            raise ValueError('Canaries must have at least 32 bytes')
        text = canary.decode('utf-8')
        variants = {'raw': canary, 'base64': base64.b64encode(canary),
                    'base64url': base64.urlsafe_b64encode(canary), 'hex': canary.hex().encode(),
                    'url': urllib.parse.quote(text, safe='').encode(),
                    'json': json.dumps(text, ensure_ascii=True)[1:-1].encode()}
        for category, variant in variants.items():
            if variant in raw or re.sub(rb'\s+', b'', variant) in compact:
                categories.add(category)
        # Catch partial/split fragments too; do not publish the matching fragment.
        if any(canary[i:i+16] in raw for i in range(0, len(canary)-15, 16)):
            categories.add('fragment')
    return {'surface': surface, 'leakDetected': bool(categories), 'categories': sorted(categories),
            'inputDigest': hashlib.sha256(raw).hexdigest(), 'inputBytes': len(raw)}
