"""Runnable disposable native private transport candidate; no production proof.

No mutation retries, exception-triggered recovery, application-source broker,
provider-side SQL updates, or generic volume-destructive deletion.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import select
import subprocess
import time
import urllib.error
import urllib.request

from private_commands import bootstrap_command, START_COMMAND
from private_collect import (
    capture, full_provider_logs, image_evidence, observe_helper, provider_create_exception,
    provider_log_cursor, verify_missing_refusal,
)
from private_leaks import scan_canaries
from private_storage import prestart_gate
from private_throwable import DIAGNOSTIC_HEADER, ObserverInstallFailure, TypedCreateObserver, provider_artifact_evidence
from revision_identity import checks as identity_checks
from revision_inventory import read_containers
from revision_wait import wait_for_removal

CAPABILITY = 'VN_ARTIFACT_CAPABILITY'
LITERAL_SUFFIX = '-$literal\n${CHANGED_PROVIDER_ENV}\n"quote"'
LIMITS = {'web': (402653184,375000000,128), 'redis': (134217728,125000000,64)}
PHP_BOOT = 'require "vendor/autoload.php"; $app=require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); '


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def digest(value): return hashlib.sha256(value).hexdigest()


def preflight():
    if (os.name != 'posix' or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('VN_PRIVATE_DISPOSABLE') != '1' or
            any(os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY'))):
        raise RuntimeError('Disposable local Actions host required')
    sha = os.environ['GITHUB_SHA']
    if os.environ.get('VN_PRIVATE_REVIEWED_SHA') != sha or capture(['git','rev-parse','HEAD']).decode().strip() != sha:
        raise RuntimeError('Reviewed source identity required')
    if os.environ['GITHUB_REPOSITORY'] != 'NikitaBabenko/vibenest-compose-contract-fixture':
        raise RuntimeError('Synthetic fixture repository required')
    return sha


class Broker:
    def __init__(self, executable, ip):
        self.process = subprocess.Popen([executable,'broker','--helper='+executable,'--ip='+ip],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try: self.info = self.read()
        except Exception:
            self.process.kill(); self.process.wait(timeout=10)
            self.process.stdin.close(); self.process.stdout.close()
            raise

    def read(self):
        if not select.select([self.process.stdout], [], [], 25)[0]: raise RuntimeError('Broker reply unknown')
        raw = self.process.stdout.readline((12 << 20)+1)
        if not raw.endswith(b'\n') or len(raw) > 12 << 20: raise RuntimeError('Broker response incomplete')
        return json.loads(raw)

    def call(self, **request):
        self.process.stdin.write(encoded(request)+b'\n'); self.process.stdin.flush()
        return self.read()

    def close(self):
        self.process.stdin.close()
        try: self.process.wait(timeout=10)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=10)
        self.process.stdout.close()


class NativeFixture:
    def __init__(self, executable, utility_image):
        self.sha = preflight(); self.utility_image = utility_image
        self.evidence = pathlib.Path('evidence/private'); self.evidence.mkdir(parents=True,exist_ok=True)
        self.private = pathlib.Path('/tmp/vn-private-runner'); self.private.mkdir(mode=0o700,exist_ok=False)
        self.token = pathlib.Path('/tmp/coolify-contract-token').read_text().strip()
        self.canaries = []; self.user_canaries = []; self.apps = []; self.scans = []; self.scopes = []; self.env_keys = set()
        self.literal = 'synthetic-'+secrets.token_hex(24)+LITERAL_SUFFIX
        self.observations = {}; self.prefix = 'vnprivate'+os.environ['GITHUB_RUN_ID']
        self.volumes = {'app-data': self.prefix+'-web', 'redis-data': self.prefix+'-redis'}
        self.intents = {key: secrets.token_hex(32) for key in self.volumes}
        self.initial_volume_names=sorted(capture(['docker','volume','ls','-q']).decode().split())
        self.expected_volume_names=sorted(self.initial_volume_names+list(self.volumes.values()))
        tracked=capture(['git','ls-files','--stage','-z']).decode().split('\0')
        self.source_files={}
        for entry in filter(None,tracked):
            meta,p=entry.split('\t',1);mode,_,stage=meta.split()
            if mode not in ('100644','100755') or stage!='0': raise RuntimeError('Unsupported source index entry')
            if p not in ('private-compose.yaml','private-app/Dockerfile'):
                self.source_files[p]={'digest':digest(pathlib.Path(p).read_bytes()),'mode':int(mode[-3:],8)}
        body=pathlib.Path('private-app/Dockerfile').read_text().strip()
        self.dockerfile_body_digest=digest(body.encode())
        self.result = {'sourceSha':self.sha, 'productionEnablementAllowed':False,'platformGatesTested':False,
            'hostProofTested':False,'routeCasTested':False,'concurrentExternalWritersFenced':False,
            'cloudBinaryParity':'unknown','nativePrivateTransport':'failed_or_unproven','steps':[]}
        gateway = json.loads(capture(['docker','network','inspect','coolify']))[0]['IPAM']['Config'][0]['Gateway']
        self.broker = Broker(executable,gateway)
        helper_sources={str(p).replace('\\','/'):digest(p.read_bytes()) for p in pathlib.Path('bench/private').rglob('*.go') if not p.name.endswith('_test.go')}
        helper_sources['bench/private/go.mod']=digest(pathlib.Path('bench/private/go.mod').read_bytes())
        renderer_sources={p:digest(pathlib.Path(p).read_bytes()) for p in ('bench/private_render.py','bench/private_storage.py','bench/private-render.Dockerfile')}
        self.save('implementation-identity',{'sourceSha':self.sha,'goToolchain':'go1.27.4',
            'helperBinaryDigest':self.broker.info['helperDigest'],'helperBytes':self.broker.info['helperSize'],
            'helperSourceHashes':helper_sources,'helperSourceManifestDigest':digest(encoded(helper_sources)),
            'publicLoaderDigest':digest(pathlib.Path('bench/private-loader.sh').read_bytes()),
            'rendererKind':'fixture Python in isolated utility container','rendererImageId':self.utility_image,
            'rendererSourceHashes':renderer_sources,'platformRendererParticipates':False,
            'productionRenderer2Acceptance':False})
        self.build_command = bootstrap_command(os.environ['GITHUB_REPOSITORY'],self.sha,self.broker.info)

    def save(self, name, value):
        raw = encoded(value)
        secrets_to_check=self.canaries+self.user_canaries
        if secrets_to_check and scan_canaries(raw,secrets_to_check,surface='error')['leakDetected']:
            raise RuntimeError('Unsafe evidence serialization refused')
        (self.evidence/(name+'.json')).write_bytes(raw)

    def stage(self, name):
        self.result['currentStage']=name; self.save('result',self.result)

    def api(self, path, method='GET', data=None):
        observe_create=(path=='/applications/public' and method=='POST' and
                        self.result.get('currentStage')=='provider-first-application-create')
        typed_observer=None
        headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/json'}
        if observe_create and os.environ.get('VN_PRIVATE_TYPED_DIAGNOSTIC')=='1':
            typed_observer=TypedCreateObserver()
            try:
                installation=typed_observer.install()
            except ObserverInstallFailure as error:
                self.save('provider-create-exception',error.evidence)
                raise RuntimeError('Disposable Throwable observer could not be installed') from None
            self.save('provider-observer-install',installation)
            readiness=typed_observer.await_fpm()
            self.save('provider-fpm-readiness',readiness)
            if readiness.get('observation')!='patched-fpm-ready':
                raise RuntimeError('Disposable patched FPM entrypoint was not verified')
            headers[DIAGNOSTIC_HEADER]=typed_observer.nonce
        provider_cursor=provider_log_cursor() if observe_create and typed_observer is None else None
        request = urllib.request.Request('http://127.0.0.1:8000/api/v1'+path,method=method,
            headers=headers,
            data=encoded(data) if data is not None else None)
        try:
            with urllib.request.urlopen(request,timeout=30) as response: raw=response.read(16<<20)
        except urllib.error.HTTPError as exc:
            raw=exc.read(1<<20)
            self.scans.append(scan_canaries(raw,self.canaries,surface='error')) if self.canaries else None
            refusal={'status':exc.code,'method':method}
            if path in ('/projects','/applications/public'):
                refusal['path']=path
                try:
                    body=json.loads(raw)
                except ValueError:
                    body={}
                errors=body.get('errors') if isinstance(body,dict) else None
                if isinstance(errors,dict):
                    refusal['rejectedFields']=sorted(set(data or {}).intersection(errors))
            self.save('api-refusal',refusal)
            if observe_create and exc.code==500:
                evidence=typed_observer.read() if typed_observer is not None else provider_create_exception(provider_cursor)
                self.save('provider-create-exception',evidence)
            raise RuntimeError('Native API refused') from None
        except Exception: raise RuntimeError('Native API outcome unknown; no retry') from None
        try: return json.loads(raw)
        except ValueError:
            if path=='/version': return raw.decode().strip()
            raise RuntimeError('Native API response refused') from None

    def php(self, code): return capture(['docker','exec','coolify','php','-r',PHP_BOOT+code])

    def commands_preflight(self):
        examples=[self.build_command, START_COMMAND, 'true '+'a'*994, 'true '+'a'*995, 'true '+'a'*996, 'true\ntrue']
        payload=base64.b64encode(encoded(examples)).decode()
        code="$v=json_decode(base64_decode('"+payload+"'),true);$o=[];foreach($v as $s){$o[]=Illuminate\\Support\\Facades\\Validator::make(['command'=>$s],['command'=>App\\Support\\ValidationPatterns::shellSafeCommandRules()])->passes();}echo json_encode($o);"
        accepted=json.loads(self.php(code))
        self.save('command-validation',{'lengths':list(map(len,examples)),'accepted':accepted})
        if accepted!=[True,True,True,True,False,False]: raise RuntimeError('Pinned command validator contract mismatch')
        # Exercise actual provider transformation functions with synthetic values.
        code="$v=json_decode(base64_decode('"+payload+"'),true);$o=[];foreach(array_slice($v,0,2) as $s){if(!str($s)->contains('--project-directory'))$s=str($s)->replaceFirst('compose','compose --project-directory /artifacts/test')->value();$s=injectDockerComposeFlags($s,'/artifacts/test/private-compose.yaml','/artifacts/build-time.env');$s=injectDockerComposeBuildArgs($s,'--build-arg NEVER_A_REAL_SECRET=value');$o[]=$s;}echo json_encode($o);"
        transformed=json.loads(self.php(code))
        if transformed!=examples[:2]: raise RuntimeError('Native command unexpectedly rewritten')
        self.save('command-transforms',{'unchanged':True,'digests':[digest(x.encode()) for x in transformed]})

    def command_api_boundaries(self, app):
        statuses=[]
        for length in (999,1000,1001):
            request=urllib.request.Request('http://127.0.0.1:8000/api/v1/applications/'+app,method='PATCH',
                headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Accept':'application/json'},
                data=encoded({'docker_compose_custom_build_command':'true '+'a'*(length-5)}))
            try:
                with urllib.request.urlopen(request,timeout=30) as response:
                    response.read(1<<20);statuses.append(response.status)
            except urllib.error.HTTPError as exc:
                exc.read(1<<20);statuses.append(exc.code)
        self.save('command-api-boundaries',{'lengths':[999,1000,1001],'statuses':statuses})
        self.api('/applications/'+app,'PATCH',{'docker_compose_custom_build_command':self.build_command})
        if statuses[:2]!=[200,200] or statuses[2]!=422: raise RuntimeError('Actual API command length contract mismatch')

    def identity(self, app):
        actual=self.api('/applications/'+app)
        if not all(identity_checks(actual,app,os.environ['GITHUB_REPOSITORY'],os.environ['GITHUB_REF_NAME'],self.sha).values()):
            raise RuntimeError('Native source anchor mismatch')
        if actual.get('fqdn') not in (None,''): raise RuntimeError('Unexpected global domain build variables')
        if not app.isalnum(): raise RuntimeError('Invalid native identity')
        code="$a=App\\Models\\Application::where('uuid','"+app+"')->sole();echo json_encode(['parser'=>(string)$a->compose_parsing_version,'preserve'=>(bool)$a->settings->is_preserve_repository_enabled,'raw'=>(bool)$a->settings->is_raw_compose_deployment_enabled,'secrets'=>(bool)$a->settings->use_build_secrets,'buildServer'=>(bool)$a->settings->is_build_server_enabled,'defaults'=>(bool)$a->settings->include_coolify_default_variables,'commitArg'=>(bool)$a->settings->include_source_commit_in_build,'argInsertion'=>(bool)$a->settings->inject_build_args_to_dockerfile]);"
        profile=json.loads(self.php(code))
        if profile!={'parser':'5','preserve':False,'raw':False,'secrets':False,'buildServer':False,'defaults':False,'commitArg':False,'argInsertion':True}:
            raise RuntimeError('Unsupported native profile')
        return actual

    def env(self, app, key, value, *, build=False, runtime=False, locked=False):
        identity=(app,key)
        if key=='FIXTURE_LITERAL':
            self.user_canaries.append(value);locked=True
        result=self.api('/applications/'+app+'/envs','PATCH' if identity in self.env_keys else 'POST',
            {'key':key,'value':value,'is_buildtime':build,'is_runtime':runtime,'is_literal':True,
             'is_preview':False,'is_shown_once':locked,'is_multiline':'\n' in value})
        self.env_keys.add(identity)
        if key=='FIXTURE_LITERAL':
            code="$a=App\\Models\\Application::where('uuid','"+app+"')->sole();$e=$a->environment_variables->where('key','FIXTURE_LITERAL')->sole();echo json_encode(['build'=>(bool)$e->is_buildtime,'runtime'=>(bool)$e->is_runtime,'locked'=>(bool)$e->is_shown_once,'literal'=>(bool)$e->is_literal,'multiline'=>(bool)$e->is_multiline]);"
            metadata=json.loads(self.php(code))
            if metadata!={'build':False,'runtime':True,'locked':True,'literal':True,'multiline':'\n' in value}:
                raise RuntimeError('Runtime user ENV metadata mismatch')
            self.save('runtime-env-flags-'+app,metadata)
        return result

    def create(self, name, domain, *, diagnostic_only=False):
        app=self.api('/applications/public','POST',{'name':name,'project_uuid':self.project,
            'environment_name':'production','server_uuid':self.server['uuid'],
            'git_repository':'https://github.com/'+os.environ['GITHUB_REPOSITORY'],
            'git_branch':os.environ['GITHUB_REF_NAME'],'git_commit_sha':self.sha,'build_pack':'dockercompose',
            'ports_exposes':'3000','docker_compose_location':'/private-compose.yaml',
            'autogenerate_domain':False,
            'docker_compose_domains':[{'name':'web','domain':'http://'+domain+':3000'}],
            'docker_compose_custom_build_command':self.build_command,'docker_compose_custom_start_command':START_COMMAND,
            'use_build_server':False,'use_build_secrets':False,'is_preserve_repository_enabled':False,
            'inject_build_args_to_dockerfile':True,
            'include_coolify_default_variables':False,'include_source_commit_in_build':False,
            'is_raw_compose_deployment_enabled':False,'is_auto_deploy_enabled':False,
            'is_preview_deployments_enabled':False,'instant_deploy':False})['uuid']
        self.apps.append(app)
        if diagnostic_only:
            return app
        self.identity(app)
        if read_containers(app): raise RuntimeError('Create launched application')
        self.env(app,'FIXTURE_LITERAL',self.literal,runtime=True)
        self.env(app,'FIXTURE_BUILD_ALLOWED','allowed-build-dollar$fixture',build=True)
        return app

    def volumes_snapshot(self):
        names=capture(['docker','volume','ls','-q']).decode().split()
        if len(names)!=len(set(names)): raise RuntimeError('Volume inventory ambiguous')
        result={}
        for key,name in self.volumes.items():
            if name not in names: raise RuntimeError('Retained volume missing')
            rows=json.loads(capture(['docker','volume','inspect',name]))
            if len(rows)!=1: raise RuntimeError('Volume inspection incomplete')
            row=rows[0]
            if row['Driver']!='local' or row['Scope']!='local' or row['Options'] not in (None,{}) or row['Labels']!={'fixture.intent':self.intents[key],'fixture.project':self.project}:
                raise RuntimeError('Volume ownership observation mismatch')
            result[key]=row
        return result

    def unreachable(self, domain):
        try:
            with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1',headers={'Host':domain}),timeout=3) as response:
                if response.status<400: raise RuntimeError('Application reachable before gate')
        except urllib.error.HTTPError as exc:
            if exc.code not in (404,502,503,504): raise RuntimeError('Unexpected route response') from None
        except urllib.error.URLError: pass

    def http(self, domain):
        for _ in range(20):
            try:
                with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1',headers={'Host':domain}),timeout=3) as response:
                    value=json.load(response)
                    if value.get('sqlite') is not True or value.get('uid')!=1000 or value.get('literalDigest')!=digest(self.literal.encode()):
                        raise RuntimeError('Persistence or frozen ENV check failed')
                    return value
            except (urllib.error.HTTPError,urllib.error.URLError): time.sleep(1)
        raise RuntimeError('Application did not become healthy')

    def bindings(self, app):
        return [{'service':service,'physicalName':self.volumes[key],'destination':dest,'readOnly':False,
                 'normalizedSourceKey':app+'_'+key,'declaredVolume':key}
                for service,key,dest in [('web','app-data','/app/data'),('redis','redis-data','/data')]]

    def job(self, app, domain, mode, *, retained=None, redis_image='', new=False, expected_missing_volume=None):
        self.identity(app)
        if mode!='prepare':
            for name in self.volumes.values():
                if capture(['docker','ps','-aq','--filter','volume='+name]).strip(): raise RuntimeError('Shared writer still exists')
        settings={'mode':mode,'utilityImage':self.utility_image,'volumes':self.volumes,
                  'volumeMode':'NewCreate' if new else 'RetainedInspect','intents':self.intents,
                  'volumeObservations':{} if new else self.observations,'redisImage':redis_image,'retainedScope':retained,
                  'sourceFiles':self.source_files,'dockerfileBodyDigest':self.dockerfile_body_digest}
        scope={'project':self.project,'application':app,'attempt':secrets.token_hex(16),'deployment':'',
               'generation':len(self.scopes)+1,'sourceSha':self.sha,'helperDigest':self.broker.info['helperDigest'],
               'settingsDigest':digest(encoded(settings))}
        if new:
            names=capture(['docker','volume','ls','-q']).decode().split()
            if set(names)&set(self.volumes.values()): raise RuntimeError('Initial storage collision')
            # Durable intent before dispatch; no physical marker or Docker mutation.
            with (self.private/'new-create-intent.json').open('xb') as out:
                out.write(encoded({'scope':scope,'kind':'NewCreate','volumes':self.volumes,'nonces':self.intents}));out.flush();os.fsync(out.fileno())
        grants=self.broker.call(op='issue',scope=scope,settings=settings,retainedScope=retained)
        if not grants.get('ok'): raise RuntimeError('Fixture capability issue refused')
        self.canaries.extend([grants['delivery'],grants['submission']])
        self.env(app,CAPABILITY,grants['delivery'],build=True,locked=True)
        # Verify flags without exposing the locked value.
        code="$a=App\\Models\\Application::where('uuid','"+app+"')->sole();$e=$a->environment_variables->where('key','VN_ARTIFACT_CAPABILITY')->sole();echo json_encode(['build'=>(bool)$e->is_buildtime,'runtime'=>(bool)$e->is_runtime,'locked'=>(bool)$e->is_shown_once,'literal'=>(bool)$e->is_literal,'multiline'=>(bool)$e->is_multiline]);"
        if json.loads(self.php(code))!={'build':True,'runtime':False,'locked':True,'literal':True,'multiline':False}:
            raise RuntimeError('Capability ENV profile mismatch')
        response=self.api('/applications/'+app+'/start','POST');deployment=response['deployment_uuid'];scope['deployment']=deployment
        if not deployment.isalnum(): raise RuntimeError('Native dispatch identity invalid')
        if not self.broker.call(op='bind',delivery=grants['delivery'],submission=grants['submission'],deployment=deployment).get('ok'):
            raise RuntimeError('Native dispatch binding failed')
        self.scopes.append(scope);self.save('dispatch-'+deployment,{'scope':scope,'mode':mode})
        released=False;artifact=None;terminal=None
        try:
            for _ in range(240):
                status=self.api('/deployments/'+deployment)
                if not released:
                    opened=self.broker.call(op='open',scope=scope)
                    if opened.get('ok'):
                        if expected_missing_volume is not None: raise RuntimeError('Missing-retained target produced runtime artifact')
                        commit=self.php("$q=App\\Models\\ApplicationDeploymentQueue::where('deployment_uuid','"+deployment+"')->sole();echo json_encode(['commit'=>$q->commit]);")
                        if json.loads(commit).get('commit')!=self.sha: raise RuntimeError('Actual native checkout commit mismatch')
                        self.save('source-'+deployment,{'queueCommit':self.sha,'manifestDigest':digest(encoded(self.source_files)),
                            'sourceFileCount':len(self.source_files),'generatedAllowlist':['private-compose.yaml','private-app/Dockerfile'],
                            'dockerfileOriginalDigest':self.dockerfile_body_digest,'nativeCloneOnly':True})
                        compose_version=capture(['docker','exec',deployment,'docker','compose','version','--short']).decode().strip()
                        engine_version=capture(['docker','version','--format','{{.Server.Version}}']).decode().strip()
                        if not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',compose_version): raise RuntimeError('Unknown actual Compose binary')
                        self.save('native-cli-'+deployment,{'composeVersion':compose_version,'engineVersion':engine_version,
                            'configFlags':['--env-file','/tmp/vn-private/empty.env','--project-name',app,'--project-directory','/artifacts/'+deployment,'-f','/tmp/vn-private/effective.json'],
                            'createFlags':['create','--no-build','--pull','never']})
                        artifact=opened['artifact'];self.scans.extend(observe_helper(deployment,self.canaries))
                        if mode=='prepare':
                            if read_containers(app): raise RuntimeError('Preparation launched runtime')
                        else:
                            self.unreachable(domain)
                            rows=read_containers(app)
                            gate=prestart_gate(rows,application=app,bindings=self.bindings(app),images=artifact['images'],limits=LIMITS)
                            self.save('prestart-'+deployment,gate)
                            if self.volumes_snapshot()!=self.observations: raise RuntimeError('Retained storage changed before gate')
                        if any(s['leakDetected'] for s in self.scans): raise RuntimeError('Capability leak detected')
                        if not self.broker.call(op='release',scope=scope).get('ok'): raise RuntimeError('Fixture release refused')
                        released=True
                if status.get('status') in ('finished','failed','cancelled','canceled'):
                    terminal=status['status'];break
                time.sleep(2)
            if terminal is None: raise RuntimeError('Native outcome unknown; no retry')
            if expected_missing_volume is not None:
                if released or terminal!='failed' or read_containers(app): raise RuntimeError('Expected pre-start refusal not observed')
                refusal=self.broker.call(op='refusal',scope=scope)
                if refusal.get('ok') is not True: raise RuntimeError('Specific missing-retained refusal receipt absent')
                names=capture(['docker','volume','ls','-q']).decode().split()
                verified=verify_missing_refusal(refusal.get('refusal'),scope=scope,
                    expected_name=expected_missing_volume,inventory=names,complete=True)
                self.save('missing-retained-refusal-'+deployment,verified)
            elif not released or terminal!=('failed' if mode=='fault' else 'finished'):
                raise RuntimeError('Native outcome did not match fixture phase')
            # A --rm helper must disappear; retained state cannot live in its FS.
            for _ in range(30):
                names=capture(['docker','ps','-a','--format','{{.Names}}']).decode().splitlines()
                if deployment not in names: break
                time.sleep(1)
            else: raise RuntimeError('Native helper was preserved')
            volume_names=sorted(capture(['docker','volume','ls','-q']).decode().split())
            self.save('volume-inventory-'+deployment,{'beforeInitial':self.initial_volume_names,'after':volume_names,
                'addedSinceInitial':sorted(set(volume_names)-set(self.initial_volume_names)),'assigned':self.expected_volume_names})
            if volume_names!=self.expected_volume_names: raise RuntimeError('Unexpected physical volume inventory delta')
            self.result['steps'].append({'mode':mode,'deployment':deployment,'helperRemoved':True,
                'expectedRefusal':expected_missing_volume is not None,
                'configDigest':artifact['effectiveConfigDigest'] if artifact else None,
                'images':artifact['images'] if artifact else None})
            self.save('result',self.result)
            return scope,artifact
        finally:
            # Revocation never requires cleanup API success. No automatic launch.
            self.broker.call(op='revoke',capability=grants['delivery'])
            self.broker.call(op='revoke',capability=grants['submission'])

    def stop(self, app):
        self.identity(app);self.api('/applications/'+app+'/stop','POST',{'docker_cleanup':False})
        wait_for_removal(lambda deadline:read_containers(app,deadline=deadline),read_with_deadline=True)
        if self.volumes_snapshot()!=self.observations: raise RuntimeError('Storage lost during native stop')

    def revoked_provider_restart(self, app, domain, baseline):
        def stable(rows):
            return sorted((r['Id'],r['Image'],r['State']['StartedAt'],r['State']['Pid'],r['RestartCount']) for r in rows)
        before=stable(read_containers(app));self.identity(app)
        deployment=self.api('/applications/'+app+'/start','POST')['deployment_uuid']
        terminal=None
        for _ in range(120):
            status=self.api('/deployments/'+deployment)
            if status.get('status') in ('finished','failed','cancelled','canceled'):
                terminal=status['status'];break
            time.sleep(2)
        if terminal!='failed' or stable(read_containers(app))!=before or self.http(domain)!=baseline:
            raise RuntimeError('Revoked provider-only restart was not safely refused')
        self.save('revoked-provider-restart',{'deployment':deployment,'terminal':'failed','oldRuntimeUntouched':True})

    def run(self):
        try:
            self.stage('provider-preflight')
            self.save('provider-artifact',provider_artifact_evidence(pathlib.Path('evidence/provider-artifact.json')))
            version=self.api('/version')
            if version not in ('4.7.5', {'version':'4.7.5'}): raise RuntimeError('Unsupported provider version')
            self.commands_preflight()
            self.server=self.api('/servers')[0]
            self.stage('provider-project-create')
            self.project=self.api('/projects','POST',{'name':'Private native transport fixture'})['uuid']
            self.stage('provider-first-application-create')
            typed_diagnostic=os.environ.get('VN_PRIVATE_TYPED_DIAGNOSTIC')=='1'
            old=self.create('private-retained','private-old.contract.localhost',diagnostic_only=typed_diagnostic)
            if typed_diagnostic:
                self.result['typedCreateDiagnostic']='provider-create-accepted'
                return
            self.command_api_boundaries(old)
            self.stage('prepare-old-native-new-storage')
            retained,old_artifact=self.job(old,'private-old.contract.localhost','prepare',new=True)
            self.observations=self.volumes_snapshot()
            self.stage('activate-old-fresh-helper')
            self.env(old,'FIXTURE_LITERAL','changed-'+secrets.token_hex(24),runtime=True)
            self.job(old,'private-old.contract.localhost','activate',retained=retained)
            baseline=self.http('private-old.contract.localhost');self.save('baseline',baseline)
            self.stage('revoked-provider-only-restart-refused')
            self.revoked_provider_restart(old,'private-old.contract.localhost',baseline)
            candidate=self.create('private-candidate','private-candidate.contract.localhost')
            self.stage('prepare-candidate-retained-inspect')
            prepared,candidate_artifact=self.job(candidate,'private-candidate.contract.localhost','prepare',redis_image=old_artifact['images']['redis'])
            if self.http('private-old.contract.localhost')!=baseline: raise RuntimeError('Prepare changed old writer')
            self.stage('candidate-fresh-activate')
            self.stop(old);self.env(candidate,'FIXTURE_LITERAL','changed-'+secrets.token_hex(24),runtime=True)
            self.job(candidate,'private-candidate.contract.localhost','activate',retained=prepared)
            active=self.http('private-candidate.contract.localhost')
            for key in ('marker','redisSentinelDigest','literalDigest'):
                if active[key]!=baseline[key]: raise RuntimeError('Persisted state changed')
            self.save('candidate-active',active)
            self.stage('candidate-fault-before-write')
            self.stop(candidate)
            self.job(candidate,'private-candidate.contract.localhost','fault',retained=prepared)
            failed=read_containers(candidate)
            if not any(r['Config']['Labels']['com.docker.compose.service']=='web' and r['State']['ExitCode']==42 for r in failed):
                raise RuntimeError('Controlled failure not observed')
            self.stop(candidate)
            self.stage('missing-retained-target-refused-without-create')
            original_name=self.volumes['app-data']
            missing='vnprivate'+os.environ['GITHUB_RUN_ID']+'1-web'
            if missing in capture(['docker','volume','ls','-q']).decode().split(): raise RuntimeError('Negative target collision')
            self.volumes['app-data']=missing
            try:
                self.job(old,'private-old.contract.localhost','activate',retained=retained,expected_missing_volume=missing)
                if missing in capture(['docker','volume','ls','-q']).decode().split(): raise RuntimeError('Missing retained target recreated')
            finally: self.volumes['app-data']=original_name
            if self.volumes_snapshot()!=self.observations: raise RuntimeError('Negative test changed retained storage')
            self.stage('recover-old-fresh-helper-exact-artifact')
            self.job(old,'private-old.contract.localhost','activate',retained=retained)
            recovered=self.http('private-old.contract.localhost')
            for key in ('marker','redisSentinelDigest','literalDigest'):
                if recovered[key]!=baseline[key]: raise RuntimeError('Recovered state changed')
            if recovered['boots']!=active['boots']+1: raise RuntimeError('Fault wrote SQLite state')
            self.save('recovered',recovered)
            self.stage('full-transport-leak-evidence')
            self.scans.append(full_provider_logs(self.apps,self.canaries+self.user_canaries))
            self.scans.extend(image_evidence(list(old_artifact['images'].values())+list(candidate_artifact['images'].values()),self.canaries+self.user_canaries))
            for app in self.apps:
                self.scans.append(scan_canaries(encoded(read_containers(app)),self.canaries,surface='runtime-env'))
            if any(s['leakDetected'] for s in self.scans): raise RuntimeError('Transport capability leaked')
            self.result['nativePrivateTransport']='passed_in_disposable_fixture_only'
            self.result['productionEnablementAllowed']=False
        except Exception as exc:
            self.result['failureType']=type(exc).__name__
            raise RuntimeError('Private native fixture failed; see sanitized result stage') from None
        finally:
            leaked=False
            try:
                if self.apps and self.canaries: self.scans.append(full_provider_logs(self.apps,self.canaries+self.user_canaries))
                leaked=any(s['leakDetected'] for s in self.scans)
                if leaked: self.result['nativePrivateTransport']='failed_or_unproven'
                self.save('scans',self.scans);self.save('result',self.result)
            finally: self.broker.close()
            if leaked: raise RuntimeError('Capability leak detected in final evidence')


def main():
    import sys
    if len(sys.argv)!=3: raise SystemExit('Usage: private_native.py NATIVE_BINARY UTILITY_IMAGE_ID')
    NativeFixture(sys.argv[1],sys.argv[2]).run()


if __name__=='__main__': main()
