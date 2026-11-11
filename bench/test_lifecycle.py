import copy
import json
import pathlib
import subprocess
import sys
import unittest

from lifecycle_assertions import classify_case, preserved_runtime, unchanged_http


def runtime():
    return [{'id':name+'-old', 'service':name, 'imageId':'sha256:'+name, 'state':'running',
             'memory':128, 'nanoCpus':125000000, 'ports':{}, 'mounts':[{'Name':name+'-data','RW':True}],
             'networks':['app']} for name in ('web','redis')]


class EvidenceTests(unittest.TestCase):
    def test_prior_running_revision_preserved(self):
        before=runtime()
        self.assertTrue(preserved_runtime(before, copy.deepcopy(before)))

    def test_empty_runtime_reproduces_previous_bench_failure(self):
        self.assertFalse(preserved_runtime(runtime(), []))

    def test_web_alone_is_insufficient(self):
        self.assertFalse(preserved_runtime(runtime(), runtime()[:1]))

    def test_new_revision_healthy_is_not_old_revision_preserved(self):
        after=runtime();after[0]['id']='web-new'
        self.assertFalse(preserved_runtime(runtime(), after))

    def test_second_writer_or_extra_container_rejected(self):
        after=runtime();extra=copy.deepcopy(after[0]);extra['id']='web-new';after.append(extra)
        self.assertFalse(preserved_runtime(runtime(), after))

    def test_missing_identity_not_treated_as_match(self):
        before=runtime();del before[0]['imageId']
        self.assertFalse(preserved_runtime(before, copy.deepcopy(before)))

    def test_mutated_image_mount_or_limits_rejected(self):
        for field,value in [('imageId','other'),('memory',0),('nanoCpus',0),('mounts',[]),('ports',{'3000/tcp':[]})]:
            with self.subTest(field=field):
                after=runtime();after[0][field]=value
                self.assertFalse(preserved_runtime(runtime(), after))

    def test_restarted_process_is_distinct_from_preservation(self):
        before={'marker':'m','boots':1,'redis':'+PONG'}
        after={**before,'boots':2}
        self.assertFalse(unchanged_http(before, after))

    def test_config_overwrite_or_unknown_rejected_even_if_runtime_healthy(self):
        state={'marker':'m','boots':1,'redis':'+PONG'}
        for before,after in [({'env':'old'},{'env':'new'}),({'env':None},{'env':None})]:
            result=classify_case(runtime(),runtime(),state,state,before,after)
            self.assertTrue(result['previousRuntimePreserved'])
            self.assertFalse(result['preserved'])


class RendererFaultTests(unittest.TestCase):
    def render(self, mode, doc):
        return subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('render.py')),mode],
                              input=json.dumps(doc),text=True,capture_output=True)

    def doc(self):
        return {'services':{name:{'image':'fixture','ports':['1:1'],'env_file':['.env'],
                                  'volumes':[{'type':'volume','source':name+'-data','target':'/data'}]}
                            for name in ['web','redis']}}

    def test_fault_reaches_start_without_executing_user_writer(self):
        r=self.render('failstart',self.doc());self.assertEqual(r.returncode,0,r.stderr)
        doc=json.loads(r.stdout);web=doc['services']['web']
        self.assertEqual(web['entrypoint'],['/bin/sh','-c','echo VIBENEST_CONTRACT_CANDIDATE_EXIT_BEFORE_WRITES; exit 42'])
        self.assertEqual(web['restart'],'no');self.assertEqual(web['command'],[])
        self.assertTrue(web['volumes'])
        for s in doc['services'].values():
            self.assertNotIn('ports',s);self.assertIn('mem_limit',s);self.assertIn('cpus',s)

    def test_original_start_does_not_get_fault(self):
        r=self.render('start',self.doc());self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn('entrypoint',json.loads(r.stdout)['services']['web'])

    def test_mount_rejection_precedes_fault_start(self):
        doc=self.doc();doc['services']['web']['volumes'][0]['type']='bind'
        self.assertNotEqual(self.render('failstart',doc).returncode,0)

    def test_build_does_not_copy_runtime_env(self):
        r=self.render('build',self.doc());self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn('env_file',json.loads(r.stdout)['services']['web'])

    def test_unknown_mode_fails_closed(self):
        self.assertNotEqual(self.render('typo',self.doc()).returncode,0)


if __name__=='__main__':
    unittest.main()
