"""Read-only, bounded snapshots while native stop removes containers concurrently."""
import json
import re
import subprocess
import time

_ID = re.compile(r'[a-f0-9]{64}\Z')
_MISSING = re.compile(r'(?:(?:error response from daemon|error): )?no such (?:object|container): ([a-f0-9]{64})', re.I)


def read_containers(application, *, deadline=None, now=time.monotonic,
                    execute=subprocess.check_output):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', application):
        raise ValueError('Invalid application identity')
    deadline = now() + 30 if deadline is None else deadline

    def command(args):
        remaining = deadline - now()
        if remaining <= 0:
            raise TimeoutError('Inventory deadline exceeded')
        return execute(['docker', *args], text=True, stderr=subprocess.PIPE,
                       timeout=min(10, remaining))

    def enumerate_ids():
        ids = command(['ps', '-aq', '--no-trunc', '--filter',
                       'label=com.docker.compose.project=' + application]).split()
        if len(ids) > 32 or len(set(ids)) != len(ids) or any(not _ID.fullmatch(x) for x in ids):
            raise RuntimeError('Invalid container enumeration')
        return sorted(ids)

    for _ in range(3):
        ids = enumerate_ids()
        if not ids:
            return []  # A successful complete enumeration, never an inspection error.
        try:
            raw = command(['inspect', *ids])
        except subprocess.CalledProcessError as error:
            lines = (error.stderr or '').strip().splitlines()
            missing = [_MISSING.fullmatch(line.strip()) for line in lines]
            if error.returncode != 1 or not missing or any(
                    match is None or match[1] not in ids for match in missing):
                raise
            # Only a specifically identified deletion race is retryable. Discard partial
            # stdout and obtain a whole new snapshot; never turn the error into absence.
            continue
        rows = json.loads(raw)
        if (not isinstance(rows, list) or len(rows) != len(ids)
                or any(not isinstance(row, dict) for row in rows)
                or sorted(row.get('Id', '') for row in rows) != ids
                or any(row.get('Config', {}).get('Labels', {}).get('com.docker.compose.project')
                       != application for row in rows)):
            raise RuntimeError('Invalid container inspection')
        if enumerate_ids() == ids:
            return rows
        # A changed set requires another complete snapshot within the SAME deadline.
    raise RuntimeError('Container inventory remained unstable; no successor start')
