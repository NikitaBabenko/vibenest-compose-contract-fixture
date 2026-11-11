"""Execute the real shell helper against a Docker stub; no engine or network."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

BASH = shutil.which('bash') if os.name != 'nt' else 'C:/Program Files/Git/bin/bash.exe'
HELPER = pathlib.Path(__file__).with_name('helper.sh').resolve().as_posix()
STUB = r'''
docker() {
  printf '%s\0' "$@" >> calls
  printf '\n' >> calls
  case "$1" in
    run) cat ;;
    compose) case " $* " in *' config '*) printf '{}\n' ;; esac ;;
  esac
}
export -f docker
bash "$@"
'''

class HelperCommandTests(unittest.TestCase):
    def run_helper(self, args):
        with tempfile.TemporaryDirectory() as folder:
            completed = subprocess.run([BASH, '-c', STUB, 'stub', HELPER, *args],
                cwd=folder, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((pathlib.Path(folder)/'unexpected-side-effect').exists())
            return [line.decode().rstrip('\0').split('\0') for line in
                    (pathlib.Path(folder)/'calls').read_bytes().split(b'\n') if line]

    def test_provider_injected_pairs_preserve_image_and_forward_exact_build_values(self):
        args=['--build-arg','VN_CONTRACT_VOLUME_PREFIX', '--build-arg',
              'COOLIFY_BUILD_SECRETS_HASH=synthetic', '--build-arg',
              'SPECIAL=space ; $(touch unexpected-side-effect) "quoted"']
        calls=self.run_helper(['7ff07aa15040','--project-directory','.','build',*args])
        self.assertIn(['run','--rm','-i','7ff07aa15040','build'],calls)
        self.assertIn(['compose','--project-directory','.','-f','.vibenest-build.json','build',*args],calls)
        pulls=[c for c in calls if 'pull' in c]
        self.assertEqual(len(pulls),1)
        self.assertNotIn('--build-arg',pulls[0])

    def test_no_injection_and_legacy_single_resource_command(self):
        expected=['compose','--project-directory','.','-f','.vibenest-build.json','build']
        self.assertIn(expected,self.run_helper(['7ff07aa15040','--project-directory','.','build']))
        self.assertIn(expected,self.run_helper(['build','7ff07aa15040','--project-directory','.']))

    def test_start_still_uses_rendered_artifact(self):
        calls=self.run_helper(['start','7ff07aa15040','--project-directory','.'])
        self.assertIn(['run','--rm','-i','7ff07aa15040','start'],calls)
        self.assertIn(['compose','--project-directory','.','-f','.vibenest-final/effective.json','up','-d'],calls)
