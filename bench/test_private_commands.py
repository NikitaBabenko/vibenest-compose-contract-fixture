import hashlib
import http.server
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import MagicMock, Mock, patch

from private_commands import LOADER_PATH, MAX_PUBLIC_LAUNCHER, MAX_STORED_COMMAND, START_COMMAND, bootstrap_command, public_launcher
from private_native import NativeFixture


class PrivateCommandTests(unittest.TestCase):
    def setUp(self):
        self.broker={'origin':'https://172.18.0.1:45678','caURL':'http://172.18.0.1:45679/ca.pem',
                     'launcherURL':'http://172.18.0.1:45679/l',
                     'caDigest':'a'*64,'helperDigest':'b'*64,'helperSize':9000000}

    def pinned(self, broker, loader=None):
        loader=LOADER_PATH.read_bytes() if loader is None else loader
        payload=public_launcher(broker,loader)
        return broker | {'publicLoaderDigest':hashlib.sha256(loader).hexdigest(),
                         'launcherDigest':hashlib.sha256(payload).hexdigest(),'launcherSize':len(payload)}

    def test_secretless_bounded_command_and_explicit_rewrite_marker(self):
        longest=self.broker | {'origin':'https://192.168.255.255:65534','caURL':'http://192.168.255.255:65535/ca.pem',
                               'launcherURL':'http://192.168.255.255:65535/l'}
        broker=self.pinned(longest)
        command=bootstrap_command('NikitaBabenko/vibenest-compose-contract-fixture','c'*40,broker)
        self.assertLessEqual(len(command.encode('ascii')),MAX_STORED_COMMAND)
        self.assertIn('--project-directory .',command)
        self.assertIn('--max-filesize 8192',command)
        self.assertNotIn(' build ',command)
        self.assertNotIn('docker compose',command)
        self.assertNotIn('Authorization',command)
        self.assertIn(broker['launcherDigest'],command)
        self.assertNotIn(broker['caDigest'],command)
        self.assertNotIn(broker['helperDigest'],command)
        self.assertIn('--project-directory .',START_COMMAND)
        with patch('private_commands.MAX_STORED_COMMAND',len(command)-1), self.assertRaisesRegex(ValueError,'boundary exceeded'):
            bootstrap_command('o/r','c'*40,broker)

    def test_bad_url_digest_and_repository_refused(self):
        pinned=self.pinned(self.broker)
        for broker in [pinned|{'origin':'http://172.18.0.1:42'}, pinned|{'caDigest':'latest'},
                       pinned|{'caURL':'http://172.18.0.1:42/ca.pem?token=secret'}, pinned|{'helperSize':2**30},
                       pinned|{'launcherURL':'http://172.18.0.2:45679/l'}, pinned|{'helperDigest':'d'*64},
                       pinned|{'launcherDigest':'e'*64}, pinned|{'publicLoaderDigest':'f'*64},
                       pinned|{'launcherSize':MAX_PUBLIC_LAUNCHER+1}]:
            with self.subTest(broker=broker),self.assertRaises(ValueError): bootstrap_command('o/r','c'*40,broker)
        with self.assertRaises(ValueError): bootstrap_command("bad';echo x",'c'*40,pinned)
        with self.assertRaisesRegex(ValueError,'Unbounded public launcher'):
            public_launcher(self.broker,b'#!/bin/sh\n'+b'x'*MAX_PUBLIC_LAUNCHER)

    def test_actual_shell_refuses_tampered_or_oversized_fetch_before_execution(self):
        shell=os.environ.get('VN_FIXTURE_TEST_SHELL') or shutil.which('sh')
        if not shell:
            self.skipTest('POSIX shell unavailable')
        commands=subprocess.run([shell,'-c','command -v curl && command -v sha256sum'],capture_output=True,timeout=10)
        if commands.returncode:
            self.skipTest('curl or sha256sum unavailable in POSIX shell')

        class FixtureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload=self.server.payload
                self.send_response(200)
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self,*args):
                pass

        loader=b'#!/bin/sh\ntest "$#" -eq 7 && test "$6" = --project-directory && test "$7" = . || exit 65\nprintf executed > marker\n'
        broker=self.pinned(self.broker,loader)
        launcher=public_launcher(broker,loader)
        with tempfile.TemporaryDirectory() as temporary, http.server.ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler) as server:
            root=pathlib.Path(temporary)
            loader_path=root/'loader.sh'
            loader_path.write_bytes(loader)
            with patch('private_commands.LOADER_PATH',loader_path):
                command=bootstrap_command('o/r','c'*40,broker)
            # Exercise the exact fetch, verification and execution sequence against a local test server.
            local=command.replace(broker['launcherURL'],f'http://127.0.0.1:{server.server_port}/l').replace('/tmp/v','./v')
            serving=threading.Thread(target=server.serve_forever,daemon=True)
            serving.start()
            try:
                for name,payload,should_execute in [('valid',launcher,True),('tampered',launcher+b'\n# substituted\n',False),
                                                     ('oversize',launcher+b'x'*MAX_PUBLIC_LAUNCHER,False)]:
                    with self.subTest(name=name):
                        server.payload=payload
                        working=root/name
                        working.mkdir()
                        result=subprocess.run([shell,'-c',local],cwd=working,capture_output=True,timeout=10)
                        self.assertEqual(result.returncode==0,should_execute,result.stderr.decode(errors='replace'))
                        self.assertEqual((working/'marker').exists(),should_execute)
            finally:
                server.shutdown()
                serving.join(timeout=5)

    def test_api_boundary_requires_stored_lengths_and_restores_pinned_command(self):
        for first_stored in (254,253):
            with self.subTest(first_stored=first_stored):
                fixture=Mock()
                fixture.token='synthetic'
                fixture.build_command='synthetic build command'
                digest=hashlib.sha256(fixture.build_command.encode()).hexdigest().encode()
                fixture.php.side_effect=(str(first_stored).encode(),b'255',digest)
                accepted=MagicMock()
                accepted.__enter__.return_value.status=200
                rejected=urllib.error.HTTPError('http://127.0.0.1:8000',422,'validation',{},io.BytesIO(b''))
                with patch('private_native.urllib.request.urlopen',side_effect=(accepted,accepted,rejected)) as api:
                    if first_stored==254:
                        NativeFixture.command_api_boundaries(fixture,'syntheticapp')
                    else:
                        with self.assertRaisesRegex(RuntimeError,'storage or validation'):
                            NativeFixture.command_api_boundaries(fixture,'syntheticapp')
                payloads=[json.loads(call.args[0].data)['docker_compose_custom_build_command'] for call in api.call_args_list]
                self.assertEqual(list(map(len,payloads)),[254,255,1001])
                fixture.api.assert_called_once_with('/applications/syntheticapp','PATCH',{'docker_compose_custom_build_command':fixture.build_command})
                self.assertEqual(fixture.save.call_args.args,('command-api-boundaries',{
                    'lengths':(254,255,1001),'statuses':[200,200,422],'storedLengths':[first_stored,255,None],
                    'restoredBootstrapVerified':True,
                }))


if __name__=='__main__':unittest.main()
