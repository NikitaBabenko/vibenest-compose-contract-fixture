"""Trusted synthetic renderer, invoked only as an immutable no-network utility.

No filesystem/ENV/source access. Native clone, dispatch, provisioning and physical
observations stay outside this pure transform. stdout is private JSON, not a log.
"""
import copy
import json
import re
import sys
from private_storage import PROVIDER_COMMIT, canonical_digest, normalize_bindings, literal_safe, prestart_gate

CAPABILITY = 'VN_ARTIFACT_CAPABILITY'


def render(request):
    mode, settings = request['mode'], request['settings']
    if mode == 'inspect':
        return prestart_gate(request['containers'], application=settings['application'],
                             bindings=request['bindings'], images=request['images'],
                             limits={'web': (402653184, 375000000, 128), 'redis': (134217728, 125000000, 64)})
    doc = copy.deepcopy(request['config'])
    if set(doc.get('services', {})) != {'web', 'redis'} or doc.get('name') != settings['application']:
        raise ValueError('Unexpected native model')
    for name, memory, cpu, pids in [('web', 402653184, '0.375', 128), ('redis', 134217728, '0.125', 64)]:
        service = doc['services'][name]
        if any(k in service for k in ('secrets', 'configs', 'devices', 'cap_add', 'pid', 'ipc', 'extends', 'develop', 'post_start', 'pre_stop', 'volumes_from')):
            raise ValueError('Unsupported fixture service option')
        if service.get('privileged') or service.get('network_mode') or CAPABILITY in service.get('environment', {}):
            raise ValueError('Unsafe fixture service option')
        build = service.get('build')
        if name == 'web':
            if service.get('command') is not None or service.get('entrypoint') is not None or service.get('user') is not None:
                raise ValueError('Unexpected web runtime override')
            if not isinstance(build, dict) or build.get('context') != settings['workdir'] or build.get('dockerfile') != 'private-app/Dockerfile':
                raise ValueError('Native build context mismatch')
            if set(build) - {'context', 'dockerfile', 'args', 'labels'}:
                raise ValueError('Unsupported build extension')
            args = build.get('args', {})
            if not isinstance(args, dict): raise ValueError('Unexpected build arguments')
            args.pop(CAPABILITY, None)
        elif (build is not None or service.get('entrypoint') is not None or
              service.get('command') != ['redis-server','--appendonly','yes','--appendfsync','always'] or
              service.get('image') != 'redis:7-alpine'):
            raise ValueError('Unexpected Redis runtime override')
        service.pop('ports', None)
        service['mem_limit'] = str(memory); service['cpus'] = cpu; service['pids_limit'] = pids
        service.setdefault('deploy', {}).setdefault('resources', {})['limits'] = {'memory': str(memory), 'cpus': cpu, 'pids': pids}
        service['restart'] = 'no'
        service.get('deploy', {}).pop('restart_policy', None)
        if mode != 'scrub': service.pop('env_file', None)
    if mode == 'scrub': return {'config': doc}
    mapped, bindings = normalize_bindings(doc, application=settings['application'], provider_commit=PROVIDER_COMMIT,
        parser_version='5', pull_request_id=0, retained_names=settings['volumes'], observed_digest=canonical_digest(doc))
    if mode == 'freeze':
        if set(request['images']) != {'web', 'redis'}: raise ValueError('Incomplete images')
        for name, service in mapped['services'].items():
            image = request['images'][name]
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', image): raise ValueError('Image not immutable')
            service.pop('build', None); service['image'] = image; service['pull_policy'] = 'never'
    elif mode != 'prepare': raise ValueError('Unknown render phase')
    return {'config': mapped, 'bindings': bindings}


def main():
    try:
        request = json.load(sys.stdin)
        result = render(request)
        json.dump(result, sys.stdout, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
    except Exception:
        print('Fixture render refused', file=sys.stderr)
        raise SystemExit(65)


if __name__ == '__main__': main()
