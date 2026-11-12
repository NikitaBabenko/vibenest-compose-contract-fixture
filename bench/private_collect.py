"""Private-scenario collector. Raw data is scanned in memory, never exported."""
import hashlib
import json
import os
import re
import select
import subprocess
import time
from private_leaks import scan_canaries


PROVIDER_LOG = '/var/www/html/storage/logs/laravel.log'
PROVIDER_EXCEPTION_CLASSES = {
    'Error', 'ErrorException', 'TypeError', 'PDOException', 'RuntimeException',
    'Illuminate\\Database\\QueryException',
    'Illuminate\\Database\\Eloquent\\MassAssignmentException',
    'Illuminate\\Database\\Eloquent\\ModelNotFoundException',
}
PROVIDER_SQL_STATES = {'22P02', '23502', '23503', '23505', '23514', '42P01', '42703'}
PROVIDER_FILES = (
    'app/Http/Controllers/Api/ApplicationsController.php',
    'app/Models/Application.php', 'app/Models/ApplicationSetting.php',
    'app/Jobs/LoadComposeFile.php',
)


def verify_missing_refusal(receipt, *, scope, expected_name, inventory, complete):
    """Require exact helper cause plus an independent complete volume inventory.

    Return hashes and typed scope only, never raw physical names or config.
    This disposable capability evidence is not host identity/production admission.
    """
    fields = {'schema', 'scope', 'stage', 'code', 'volumeNameDigest', 'inventoryDigest', 'createIssued'}
    scope_fields = {'project', 'application', 'attempt', 'deployment', 'generation', 'sourceSha', 'helperDigest', 'settingsDigest'}
    if (type(receipt) is not dict or set(receipt) != fields or type(receipt['schema']) is not int or receipt['schema'] != 1 or
            type(receipt['scope']) is not dict or set(receipt['scope']) != scope_fields or receipt['scope'] != scope or
            type(receipt['scope']['generation']) is not int or receipt['stage'] != 'retained-volume-inspection' or
            receipt['code'] != 'assigned-volume-missing' or receipt['createIssued'] is not False):
        raise ValueError('Exact missing-retained refusal receipt required')
    if (complete is not True or type(inventory) is not list or
            any(type(n) is not str or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', n) for n in inventory) or
            len(inventory) != len(set(inventory)) or not re.fullmatch(r'vnprivate[0-9]{1,20}-(web|redis)', expected_name) or expected_name in inventory):
        raise ValueError('Complete independent absence observation required')
    inventory_digest = hashlib.sha256(json.dumps(sorted(inventory), separators=(',', ':')).encode()).hexdigest()
    if receipt['volumeNameDigest'] != hashlib.sha256(expected_name.encode()).hexdigest() or receipt['inventoryDigest'] != inventory_digest:
        raise ValueError('Missing-retained observation identity mismatch')
    return receipt.copy()


def capture(args, timeout=30, limit=64 << 20):
    process = subprocess.run(args, capture_output=True, timeout=timeout)
    if process.returncode or len(process.stdout) > limit or len(process.stderr) > limit:
        raise RuntimeError('Private evidence read failed')
    return process.stdout


def provider_log_cursor():
    command = '$s=@stat($argv[1]); echo $s ? $s["ino"]." ".$s["size"] : "0 0";'
    try:
        inode, size = map(int, capture(['docker', 'exec', 'coolify', 'php', '-r', command, PROVIDER_LOG],
                                      timeout=10, limit=128).split())
        return inode, size
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        return None


def provider_exception_metadata(raw):
    text = raw.decode('utf-8', errors='replace')
    headers = list(re.finditer(r'(?m)^\[\d{4}-\d\d-\d\d [^\]\r\n]+\] [a-zA-Z0-9_-]+\.([A-Z]+): ', text))
    errors = [index for index, header in enumerate(headers) if header[1] == 'ERROR']
    if len(errors) != 1:
        return {'observation': 'ambiguous' if errors else 'missing'}
    index = errors[0]
    end = headers[index+1].start() if index+1 < len(headers) else len(text)
    record = text[headers[index].end():end]
    exception = ''
    for start in re.finditer(r' \{(?="(?:userId|exception)"\s*:)', record):
        try:
            context, end = json.JSONDecoder().raw_decode(record, start.start()+1)
        except ValueError:
            continue
        if record[end:].strip() in ('', '[]') and isinstance(context.get('exception'), (dict, str)):
            exception = context['exception']
            break
    provider_file = None
    provider_line = None
    if isinstance(exception, dict):
        exception_class = exception.get('class')
        code = exception.get('code')
        sql_state = str(code) if type(code) in (int, str) else ''
        stack = exception.get('trace')
        stack = stack if isinstance(stack, str) else ''
        file = exception.get('file')
        line = exception.get('line')
        if isinstance(file, str) and file.startswith('/var/www/html/') and type(line) is int and 0 < line <= 99999:
            provider_file, provider_line = file.removeprefix('/var/www/html/'), line
    else:
        match = re.match(r'\[object\] \(([a-zA-Z\\]+)\(code: [A-Z0-9]+\):', exception)
        exception_class = match[1] if match else None
        description, _, stack = exception.split('\n[previous exception]', 1)[0].rpartition('\n[stacktrace]\n')
        match = re.search(r'SQLSTATE\[([A-Z0-9]{5})\]', description or exception)
        sql_state = match[1] if match else ''
    if not isinstance(exception_class, str) or exception_class not in PROVIDER_EXCEPTION_CLASSES:
        return {'observation': 'unclassified'}
    result = {'observation': 'classified', 'exceptionClass': exception_class}
    if exception_class in ('PDOException', 'Illuminate\\Database\\QueryException') and sql_state in PROVIDER_SQL_STATES:
        result['sqlState'] = sql_state
    if provider_file in PROVIDER_FILES:
        return result | {'providerFile': provider_file, 'providerLine': provider_line}
    for frame in re.finditer(r'(?m)^#\d{1,3} /var/www/html/(app/[A-Za-z0-9_/]+\.php)\(([1-9][0-9]{0,4})\):', stack):
        if frame[1] in PROVIDER_FILES:
            result['providerFile'] = frame[1]
            result['providerLine'] = int(frame[2])
            break
    return result


def provider_create_exception(before):
    after = provider_log_cursor()
    if before is None or after is None:
        return {'observation': 'cursor-unavailable'}
    length = after[1]-before[1]
    if before[0] not in (0, after[0]) or not 0 <= length <= 65536:
        return {'observation': 'rotated-or-over-limit'}
    if length == 0 or after[0] == 0:
        return {'observation': 'missing'}
    command = 'echo file_get_contents($argv[1], false, null, (int)$argv[2], (int)$argv[3]);'
    try:
        raw = capture(['docker', 'exec', 'coolify', 'php', '-r', command, PROVIDER_LOG,
                       str(before[1]), str(length)], timeout=10, limit=65536)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {'observation': 'read-unavailable'}
    if len(raw) != length or provider_log_cursor() != after:
        return {'observation': 'cursor-changed'}
    return provider_exception_metadata(raw)


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
