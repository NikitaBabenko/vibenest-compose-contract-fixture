import copy
import unittest
from revision_render import prepare, pin, retain, fault
from revision_assertions import writer_trace

def doc():
    return {'services':{k:{'image':'fixture:'+k,'build':{'context':'.'},
        'environment':{'VN_CONTRACT_VOLUME_PREFIX':'vnrev123'},
        'volumes':[{'type':'volume','source':k,'target':v}]}
        for k,v in [('web','/app/data'),('redis','/data')]}}

class RevisionTests(unittest.TestCase):
    def test_candidate_references_exact_seed_volume_without_creating_it(self):
        old=prepare(doc(),'seed');candidate=prepare(doc(),'prepare')
        self.assertEqual({v['name'] for v in old['volumes'].values()},{v['name'] for v in candidate['volumes'].values()})
        self.assertTrue(all(v['external'] for v in candidate['volumes'].values()))
        self.assertFalse(any(v['external'] for v in old['volumes'].values()))

    def test_missing_or_unbounded_namespace_rejected(self):
        for prefix in ['', 'arbitrary-customer-volume','../vnrev123','vnrev123;rm -rf /']:
            value=doc();value['services']['web']['environment']['VN_CONTRACT_VOLUME_PREFIX']=prefix
            with self.assertRaises(ValueError):prepare(value,'prepare')

    def test_wrong_mount_or_bind_rejected(self):
        for key,value in [('type','bind'),('target','/var/run/docker.sock')]:
            source=doc();source['services']['web']['volumes'][0][key]=value
            with self.assertRaises(ValueError):prepare(source,'prepare')

    def test_pin_freezes_images_and_removes_rebuild(self):
        ids=['sha256:'+'1'*64,'sha256:'+'2'*64]
        pinned=pin(prepare(doc(),'seed'),ids)
        self.assertEqual(pinned['services']['redis']['image'],ids[0])
        self.assertEqual(pinned['services']['web']['image'],ids[1])
        for service in pinned['services'].values():
            self.assertNotIn('build',service);self.assertNotIn('env_file',service)
            self.assertEqual(service['pull_policy'],'never')

    def test_missing_or_mutable_image_reference_rejected(self):
        for ids in [[],['latest','latest'],['sha256:'+'1'*64]]:
            with self.assertRaises(ValueError):pin(prepare(doc(),'prepare'),ids)

    def test_unresolved_runtime_env_rejected(self):
        source=prepare(doc(),'prepare');source['services']['web']['env_file']=['.env']
        with self.assertRaises(ValueError):pin(source,['sha256:'+'1'*64,'sha256:'+'2'*64])

    def test_retained_resume_cannot_create_empty_replacement_volumes(self):
        prepared=prepare(doc(),'seed');retained=retain(prepared)
        self.assertTrue(all(v['external'] for v in retained['volumes'].values()))
        self.assertFalse(any(v['external'] for v in prepared['volumes'].values()))

    def test_fault_keeps_artifact_and_targets_application_before_writes(self):
        pinned=pin(prepare(doc(),'prepare'),['sha256:'+'1'*64,'sha256:'+'2'*64])
        copy_=copy.deepcopy(pinned);failed=fault(pinned)
        self.assertEqual(pinned,copy_)
        self.assertEqual(failed['services']['redis'],pinned['services']['redis'])
        self.assertEqual(failed['services']['web']['restart'],'no')
        self.assertIn('exit 42',failed['services']['web']['entrypoint'][2])

    def test_unknown_phase_rejected(self):
        with self.assertRaises(ValueError):prepare(doc(),'fallback')

class WriterTests(unittest.TestCase):
    def event(self,id_,action):
        return {'id':id_,'service':'web','project':'p','action':action}

    def test_serial_stop_then_start_allowed(self):
        events=[self.event('a','start'),self.event('a','die'),self.event('b','start')]
        self.assertTrue(writer_trace(events,{'p'},{'a'},{'b'}))

    def test_start_before_die_rejected_even_if_final_snapshot_good(self):
        events=[self.event('a','start'),self.event('b','start'),self.event('a','die')]
        self.assertFalse(writer_trace(events,{'p'},{'a'},{'b'}))

    def test_truncated_stream_and_missing_final_runtime_rejected(self):
        self.assertFalse(writer_trace([self.event('b','start')],{'p'},{'a'},{'b'}))
        self.assertFalse(writer_trace([self.event('a','start')],{'p'},{'a'},{'b'}))
