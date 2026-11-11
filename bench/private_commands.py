"""Secret-free native commands, tested independently of provider execution."""
import hashlib
import pathlib
import re


def bootstrap_command(repository, sha, broker):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('Invalid native source identity')
    for name in ('caDigest','helperDigest'):
        if not re.fullmatch(r'[a-f0-9]{64}', broker[name]): raise ValueError('Unpinned bootstrap')
    if not re.fullmatch(r'https://[0-9.]+:[0-9]+', broker['origin']) or not re.fullmatch(r'http://[0-9.]+:[0-9]+/ca.pem', broker['caURL']):
        raise ValueError('Unsupported broker URL')
    if not isinstance(broker['helperSize'], int) or not 0 < broker['helperSize'] <= 16 << 20:
        raise ValueError('Unbounded helper size')
    digest = hashlib.sha256(pathlib.Path(__file__).with_name('private-loader.sh').read_bytes()).hexdigest()
    url = f'https://raw.githubusercontent.com/{repository}/{sha}/bench/private-loader.sh'
    payload = f'umask 077; curl -fsS --max-time 30 --max-filesize 8192 --proto =https {url} -o /tmp/vn-loader && echo {digest}  /tmp/vn-loader | sha256sum -c - && sh /tmp/vn-loader {broker["origin"]} {broker["caURL"]} {broker["caDigest"]} {broker["helperDigest"]} {broker["helperSize"]} --project-directory .'
    command = "sh -c '"+payload+"'"
    if len(command) > 1000 or re.search(r'\sbuild(?:\s|$)',command) or 'docker compose' in command:
        raise ValueError('Provider command boundary exceeded')
    return command


START_COMMAND = '/tmp/vn-private/helper helper --phase=start --project-directory .'
# The CLI accepts this deliberate marker solely to prevent provider substring
# rewriting; it is not a path override and must remain exactly a dot.
