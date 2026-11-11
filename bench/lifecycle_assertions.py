"""Offline assertions over sanitized evidence. Never authorizes production launch."""

def preserved_runtime(before, after):
    """All prior containers must survive unchanged; a lone surviving web is insufficient."""
    if not before or any(x['state'] != 'running' for x in before):
        return False
    old = {x['id']: x for x in before}
    current = {x['id']: x for x in after}
    if len(old) != len(before) or len(current) != len(after) or set(old) != set(current):
        return False
    keys = ('service', 'imageId', 'state', 'memory', 'nanoCpus', 'ports', 'mounts', 'networks')
    return all(all(k in a and k in current[id_] and a[k] == current[id_][k] for k in keys)
               and bool(a['imageId']) for id_, a in old.items())


def unchanged_http(before, after):
    return bool(before and after and before == after and after.get('redis') == '+PONG')


def classify_case(before, after, before_http, after_http, config_before, config_after):
    runtime = preserved_runtime(before, after)
    config = bool(config_before and all(config_before.values()) and config_before == config_after)
    http = unchanged_http(before_http, after_http)
    return {'previousRuntimePreserved': runtime, 'previousRestartConfigPreserved': config,
            'previousHttpPreserved': http, 'preserved': runtime and config and http}
