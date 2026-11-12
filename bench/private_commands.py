"""Secret-free native commands, tested independently of provider execution."""
import hashlib
import ipaddress
import pathlib
import re

MAX_STORED_COMMAND = 255
MAX_PUBLIC_LAUNCHER = 8192
LOADER_PATH = pathlib.Path(__file__).with_name('private-loader.sh')
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(network) for network in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def broker_address(value, scheme, path=''):
    if not isinstance(value,str):
        raise ValueError('Unsupported broker URL')
    match = re.fullmatch(rf'{scheme}://([0-9.]{{7,15}}):([1-9][0-9]{{0,4}}){re.escape(path)}',value)
    if not match:
        raise ValueError('Unsupported broker URL')
    address, port = ipaddress.IPv4Address(match[1]), int(match[2])
    if not any(address in network for network in PRIVATE_NETWORKS) or port > 65535:
        raise ValueError('Unsupported broker address')
    return address, port


def public_launcher(broker, loader):
    origin = broker.get('origin')
    ca_url = broker.get('caURL')
    launcher_url = broker.get('launcherURL')
    tls = broker_address(origin,'https')
    ca = broker_address(ca_url,'http','/ca.pem')
    launcher = broker_address(launcher_url,'http','/l')
    if tls[0] != ca[0] or tls[1] == ca[1] or launcher != ca:
        raise ValueError('Inconsistent broker addresses')
    ca_digest, helper_digest, helper_size = broker.get('caDigest'), broker.get('helperDigest'), broker.get('helperSize')
    if any(not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{64}',value) for value in (ca_digest,helper_digest)):
        raise ValueError('Unpinned bootstrap metadata')
    if type(helper_size) is not int or not 0 < helper_size <= 16 << 20:
        raise ValueError('Unbounded helper size')
    shebang = b'#!/bin/sh\n'
    if not loader.startswith(shebang) or len(loader) <= len(shebang) or b'\r' in loader or b'\0' in loader:
        raise ValueError('Unsupported public loader')
    args = f"set -- '{origin}' '{ca_url}' '{ca_digest}' '{helper_digest}' '{helper_size}' \"$@\"\n".encode('ascii')
    payload = shebang+args+loader[len(shebang):]
    if len(payload) > MAX_PUBLIC_LAUNCHER:
        raise ValueError('Unbounded public launcher')
    return payload


def bootstrap_command(repository, sha, broker):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('Invalid native source identity')
    loader = LOADER_PATH.read_bytes()
    launcher = public_launcher(broker,loader)
    digest = hashlib.sha256(launcher).hexdigest()
    if (broker.get('publicLoaderDigest') != hashlib.sha256(loader).hexdigest() or
            broker.get('launcherDigest') != digest or type(broker.get('launcherSize')) is not int or
            broker['launcherSize'] != len(launcher)):
        raise ValueError('Public launcher identity mismatch')
    url = broker['launcherURL']
    command = (f"sh -c 'umask 077;curl -q -fsSm30 --proxy \"\" --max-filesize {MAX_PUBLIC_LAUNCHER} --proto =http "
               f'{url} -o /tmp/v && echo "{digest}  /tmp/v" |sha256sum -c - && sh /tmp/v --project-directory .\'')
    if len(command.encode('ascii')) > MAX_STORED_COMMAND or re.search(r'\sbuild(?:\s|$)',command) or 'docker compose' in command:
        raise ValueError('Provider command boundary exceeded')
    return command


START_COMMAND = '/tmp/vn-private/helper helper --phase=start --project-directory .'
# The CLI accepts this deliberate marker solely to prevent provider substring
# rewriting; it is not a path override and must remain exactly a dot.
