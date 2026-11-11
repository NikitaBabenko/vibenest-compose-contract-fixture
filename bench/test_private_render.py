import copy
import unittest
from private_render import render


class PrivateRenderTests(unittest.TestCase):
    def request(self, mode='prepare'):
        app='fixtureapp1234';work='/artifacts/deployment1234'
        return {'mode':mode,'settings':{'application':app,'workdir':work,'volumes':{'app-data':'vnprivate1-web','redis-data':'vnprivate1-redis'}},
                'config':{'name':app,'services':{
                    'web':{'image':'web:latest','build':{'context':work,'dockerfile':'private-app/Dockerfile','args':{'VN_ARTIFACT_CAPABILITY':'x'*64,'FIXTURE_BUILD_ALLOWED':'allowed-build-dollar$fixture'}},
                           'env_file':[{'path':work+'/.env','required':True}],'volumes':[{'type':'volume','source':app+'_app-data','target':'/app/data'}]},
                    'redis':{'image':'redis:7-alpine','command':['redis-server','--appendonly','yes','--appendfsync','always'],'volumes':[{'type':'volume','source':app+'_redis-data','target':'/data'}]}},
                    'volumes':{app+'_app-data':{'name':app+'_app-data'},app+'_redis-data':{'name':app+'_redis-data'}}},
                'images':{'web':'sha256:'+'1'*64,'redis':'sha256:'+'2'*64}}

    def test_scrub_keeps_native_runtime_env_resolution_and_user_build_arg(self):
        request=self.request('scrub');original=copy.deepcopy(request)
        web=render(request)['config']['services']['web']
        self.assertEqual(web['build']['args'],{'FIXTURE_BUILD_ALLOWED':'allowed-build-dollar$fixture'})
        self.assertIn('env_file',web)
        self.assertEqual(request,original)

    def test_build_excludes_runtime_env_and_freeze_removes_build(self):
        prepared=render(self.request())
        self.assertNotIn('env_file',prepared['config']['services']['web'])
        frozen=render(self.request('freeze'))
        for service in frozen['config']['services'].values():
            self.assertNotIn('build',service);self.assertEqual(service['pull_policy'],'never')
        self.assertEqual(frozen['config']['services']['web']['pids_limit'],128)

    def test_escaping_context_and_build_secret_refused(self):
        for mutate in [lambda r:r['config']['services']['web']['build'].update({'context':'/artifacts'}),
                       lambda r:r['config']['services']['web']['build'].update({'secrets':['key']}),
                       lambda r:r['config']['services']['web'].update({'command':['sh','-c','unexpected']}),
                       lambda r:r['config']['services']['redis'].update({'command':['sh','-c','unexpected']}),
                       lambda r:r['config']['services']['web'].update({'environment':{'VN_ARTIFACT_CAPABILITY':'bad'}})]:
            request=self.request();mutate(request)
            with self.assertRaises(ValueError):render(request)


if __name__=='__main__':unittest.main()
