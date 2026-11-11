"""Offline validators for the separate private fixture; no Docker mutations.

Inputs must come from the runner's independent native/engine observation. Calling
these functions with caller-authored dictionaries does not authenticate evidence.
No production gate or ownership decision is implemented here.
"""
import copy
import hashlib
import json
import re

PROVIDER_COMMIT = '378ce3735c4522ebb6b68e93b909b0511f278763'
KEY = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*\Z')
UUID = re.compile(r'[a-z0-9]{8,64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
TOPOLOGY = {'web': ('app-data', '/app/data'), 'redis': ('redis-data', '/data')}


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def normalize_bindings(doc, *, application, provider_commit, parser_version,
                       pull_request_id, retained_names, observed_digest):
    """Exact forward v5 ordinary-volume adapter, restricted to this fixture.

    It verifies the complete expected source key, not a suffix or target match.
    Null source declarations are used by the fixture. Extra declarations refuse
    until independently reviewed omission evidence is available.
    """
    if (provider_commit != PROVIDER_COMMIT or parser_version != '5' or
            pull_request_id != 0 or not UUID.fullmatch(application) or
            observed_digest != canonical_digest(doc)):
        raise ValueError('Unverified normalization identity')
    if set(doc.get('services', {})) != set(TOPOLOGY) or set(retained_names) != {'app-data', 'redis-data'}:
        raise ValueError('Unexpected fixture topology')
    if len(set(retained_names.values())) != 2 or any(not KEY.fullmatch(v) for v in retained_names.values()):
        raise ValueError('Physical volume alias or invalid name')
    expected_keys = {application + '_' + key for key, _ in TOPOLOGY.values()}
    if set(doc.get('volumes', {})) != expected_keys:
        raise ValueError('Missing or unexplained volume declaration')
    result = copy.deepcopy(doc)
    bindings = []
    for service, (declared, destination) in TOPOLOGY.items():
        key = application + '_' + declared
        declaration = doc['volumes'][key]
        if declaration != {'name': key}:
            raise ValueError('Unsupported provider declaration')
        mounts = doc['services'][service].get('volumes', [])
        if len(mounts) != 1:
            raise ValueError('Unexpected mount count')
        mount = mounts[0]
        if (set(mount) - {'type', 'source', 'target', 'read_only', 'volume'} or
                mount.get('type') != 'volume' or mount.get('source') != key or
                mount.get('target') != destination or mount.get('read_only', False) is not False or
                mount.get('volume', {}) not in ({}, {'nocopy': False})):
            raise ValueError('Mount identity or semantics changed')
        bindings.append({'service': service, 'declaredVolume': declared,
                         'normalizedSourceKey': key, 'destination': destination,
                         'readOnly': False, 'physicalName': retained_names[declared],
                         'observedDeclarationDigest': canonical_digest(declaration),
                         'observedMountDigest': canonical_digest(mount)})
        # Source stays unchanged. Only the verified top-level declaration changes.
        result['volumes'][key] = {'name': retained_names[declared], 'external': True}
    return result, bindings


def storage_decision(kind, *, name, host, expected_host, inventory, complete,
                     intent_nonce, prior_observation=None):
    """Pure typed decision; the caller must journal intent before any NewCreate.

    Returns a decision, never dispatches. A lost create ACK must use
    ReconcileUnknown with this same name/nonce, not invoke NewCreate again.
    """
    if (kind not in {'NewCreate', 'RetainedInspect', 'ReconcileUnknown'} or
            not KEY.fullmatch(name) or not complete or host != expected_host or
            not re.fullmatch(r'[a-f0-9]{64}', intent_nonce)):
        raise ValueError('Storage evidence unknown')
    names = [row.get('Name') for row in inventory]
    if len(names) != len(set(names)) or any(not isinstance(n, str) for n in names):
        raise ValueError('Incomplete or ambiguous inventory')
    matches = [row for row in inventory if row['Name'] == name]
    if kind == 'NewCreate':
        if prior_observation is not None or matches:
            raise ValueError('New volume collision or prior history')
        return {'decision': 'CreateOnceAfterDurableIntent', 'name': name, 'nonce': intent_nonce}
    if len(matches) != 1 or prior_observation is None:
        raise ValueError('Retained volume missing or unproven; creation forbidden')
    row = matches[0]
    if (row.get('Driver') != 'local' or row.get('Scope') != 'local' or row.get('Options') not in (None, {}) or
            row != prior_observation):
        raise ValueError('Physical volume identity drift')
    return {'decision': 'ObservedOnly', 'name': name, 'observationDigest': canonical_digest(row)}


def prestart_gate(containers, *, application, bindings, images, limits):
    """Validate complete independently read docker inspect rows before start.

    A Docker name/label is not a global immutable volume incarnation identity.
    Quiescence, fresh retained inventory and delivery revocation are separate.
    """
    if len(containers) != 2 or set(images) != set(TOPOLOGY) or set(limits) != set(TOPOLOGY):
        raise ValueError('Incomplete pre-start evidence')
    if len(bindings) != 2 or {b['service'] for b in bindings} != set(TOPOLOGY):
        raise ValueError('Incomplete bindings')
    by_service = {b['service']: b for b in bindings}
    seen = set()
    for row in containers:
        config, hostconfig, state = row['Config'], row['HostConfig'], row['State']
        labels = config['Labels']
        service = labels.get('com.docker.compose.service')
        if service not in TOPOLOGY or service in seen or labels.get('com.docker.compose.project') != application:
            raise ValueError('Unexpected container identity')
        seen.add(service)
        expected_image = images[service]
        if not IMAGE.fullmatch(expected_image) or row['Image'] != expected_image:
            raise ValueError('Image identity mismatch')
        if state.get('Status') != 'created' or state.get('Running') is not False or state.get('Restarting') is not False:
            raise ValueError('Container already started or state unknown')
        if state.get('StartedAt') not in {'0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000000000Z'}:
            raise ValueError('Container has start history')
        if (hostconfig.get('PortBindings') not in ({}, None) or hostconfig.get('PublishAllPorts') is not False or
                hostconfig.get('Privileged') is not False or not isinstance(hostconfig.get('NetworkMode'), str) or
                hostconfig['NetworkMode'] in {'', 'host', 'none'} or hostconfig['NetworkMode'].startswith('container:') or
                hostconfig.get('Binds') not in (None, []) or hostconfig.get('Devices') not in (None, []) or
                hostconfig.get('DeviceRequests') not in (None, []) or hostconfig.get('CapAdd') not in (None, []) or
                hostconfig.get('PidMode') not in (None, '') or hostconfig.get('IpcMode') == 'host'):
            raise ValueError('Unexpected host exposure')
        memory, cpus, pids = limits[service]
        if (not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (memory, cpus, pids)) or
                hostconfig.get('Memory') != memory or hostconfig.get('NanoCpus') != cpus or hostconfig.get('PidsLimit') != pids):
            raise ValueError('Resource limit mismatch')
        if service == 'web' and config.get('User') not in {'node', '1000', '1000:1000', 'node:node'}:
            raise ValueError('SQLite web must be non-root')
        mounts = row.get('Mounts', [])
        binding = by_service[service]
        if (len(mounts) != 1 or mounts[0].get('Type') != 'volume' or
                mounts[0].get('Name') != binding['physicalName'] or
                mounts[0].get('Destination') != binding['destination'] or
                mounts[0].get('RW') is not (not binding['readOnly'])):
            raise ValueError('Actual mount differs from verified binding')
    return {'checkedServices': sorted(seen), 'inspectionDigest': canonical_digest(containers),
            'productionStartAuthorized': False}


def literal_safe(value):
    """Escape resolved string VALUES before feeding frozen JSON to Compose again.

    Actual Compose re-resolution must still compare against the original model;
    this transform alone does not prove literal preservation on the target CLI.
    """
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal_safe(v) for v in value]
    if isinstance(value, dict):
        return {k: literal_safe(v) for k, v in value.items()}
    return value
