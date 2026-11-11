"""Private-scenario collector. Raw data is scanned in memory, never exported."""
import hashlib
import json
import os
import select
import subprocess
import time
from private_leaks import scan_canaries


def capture(args, timeout=30, limit=64 << 20):
    process = subprocess.run(args, capture_output=True, timeout=timeout)
    if process.returncode or len(process.stdout) > limit or len(process.stderr) > limit:
        raise RuntimeError('Private evidence read failed')
    return process.stdout


def scan_stream(args, canaries, surface, limit=1 << 30):
    # Image archives are uncompressed docker-save tar streams; no disk export.
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    digest = hashlib.sha256(); size = 0; tail = b''; categories = set()
    deadline = time.monotonic() + 180
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise RuntimeError('Private scan deadline exceeded')
            chunk = os.read(process.stdout.fileno(), 1 << 20)
            if not chunk: break
            size += len(chunk)
            if size > limit: raise RuntimeError('Private scan bound exceeded')
            digest.update(chunk)
            check = scan_canaries(tail + chunk, canaries, surface=surface)
            categories.update(check['categories']); tail = (tail + chunk)[-512:]
        if process.wait(timeout=30): raise RuntimeError('Private scan incomplete')
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=10)
        process.stdout.close()
    return {'surface': surface, 'inputDigest': digest.hexdigest(), 'inputBytes': size,
            'leakDetected': bool(categories), 'categories': sorted(categories)}


def observe_helper(deployment, canaries):
    if not deployment.isalnum(): raise ValueError('Invalid native deployment identity')
    result = [scan_stream(['docker', 'exec', deployment, 'tar', '-cf', '-', '-C', '/artifacts/'+deployment, '.'], canaries, 'context', 32 << 20)]
    result.append(scan_canaries(capture(['docker', 'exec', deployment, 'cat', '/artifacts/build-time.env']), canaries, surface='build-args'))
    helper = json.loads(capture(['docker', 'inspect', deployment]))
    result.append(scan_canaries(json.dumps(helper[0]['Config']['Env']), canaries, surface='runtime-env'))
    return result


def full_provider_logs(applications, canaries):
    if not applications or any(not a.isalnum() for a in applications): raise ValueError('Invalid fixture identities')
    # Read the persisted model logs, including hidden entries, on this disposable
    # provider only. No controller/UI filtering is treated as a complete scan.
    prefix = 'require "vendor/autoload.php"; $app=require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); '
    encoded = ','.join("'"+a+"'" for a in applications)
    php = prefix + "$ids=App\\Models\\Application::whereIn('uuid',["+encoded+"])->pluck('id'); $rows=App\\Models\\ApplicationDeploymentQueue::whereIn('application_id',$ids)->get(); if(count($rows)>30)exit(65); $size=0; foreach($rows as $r){$v=$r->getRawOriginal('logs');if(!is_string($v))exit(65);$size+=strlen($v);if($size>67108864)exit(65);echo $v,\"\\n\";}"
    raw = capture(['docker','exec','coolify','php','-r',php])
    if not raw: raise RuntimeError('Missing full provider logs')
    return scan_canaries(raw, canaries, surface='hidden-log')


def image_evidence(image_ids, canaries):
    records = []
    for image in sorted(set(image_ids)):
        if not image.startswith('sha256:') or len(image) != 71: raise ValueError('Unpinned image')
        records.append(scan_canaries(capture(['docker','history','--no-trunc','--format','{{json .}}',image]), canaries, surface='layer'))
        records.append(scan_stream(['docker','image','save',image], canaries, 'layer'))
    return records
