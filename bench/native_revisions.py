"""Native API feasibility only; no production gates or customer applications."""
import hashlib
import json
import os
import pathlib
import subprocess
import threading
import time
import urllib.request
import urllib.error
from revision_assertions import writer_trace, check_runtime
from revision_identity import checks as identity_checks
from revision_wait import wait_for_removal

assert os.environ.get('GITHUB_ACTIONS')=='true', 'Disposable runner only'
E=pathlib.Path('evidence');E.mkdir(exist_ok=True)
token=pathlib.Path('/tmp/coolify-contract-token').read_text()
image=pathlib.Path('/tmp/coolify-contract-helper').read_text().strip()
sha=os.environ['GITHUB_SHA'];branch=os.environ['GITHUB_REF_NAME']
repo='https://github.com/'+os.environ['GITHUB_REPOSITORY']
prefix='vnrev'+os.environ['GITHUB_RUN_ID']
volume_names=[prefix+'-web',prefix+'-redis']
result={'productionEnablementAllowed':False,'platformGatesTested':False,
        'privateArtifactAuthTested':False,'concurrentExternalWritersFenced':False,
        'routeCasTested':False,'cloudBinaryParity':'unknown','sourceSha':sha,
        'expectedProviderVersion':'4.7.5','steps':[]}
events=[];event_errors=[]
stream=subprocess.Popen(['docker','events','--filter','type=container','--format','{{json .}}'],
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
def collect_events():
    try:
        for line in stream.stdout:
            e=json.loads(line);a=e.get('Actor',{});labels=a.get('Attributes',{})
            if len(events)>=10000:
                event_errors.append('event_limit');break
            events.append({'timeNano':e.get('timeNano'),'action':e.get('Action'),'id':a.get('ID'),
                           'project':labels.get('com.docker.compose.project'),'service':labels.get('com.docker.compose.service')})
    except Exception:event_errors.append('event_stream_error')
event_thread=threading.Thread(target=collect_events,daemon=True);event_thread.start()

def save(name,value):
    (E/(name+'.json')).write_text(json.dumps(value,indent=2))

def checkpoint(name,value):
    result['steps'].append(name);save(name,value);save('native-revisions-result',result)

def stage(name):
    result['currentStage']=name
    save('native-revisions-result',result)

def api(path,method='GET',data=None):
    req=urllib.request.Request('http://127.0.0.1:8000/api/v1'+path,method=method,
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'},
        data=json.dumps(data).encode() if data is not None else None)
    # No mutation retries or compensation on a lost response.
    try:
        with urllib.request.urlopen(req,timeout=30) as response:
            raw=response.read().decode()
            try:return json.loads(raw)
            except json.JSONDecodeError:
                if path=='/version':return raw.strip()
                raise
    except urllib.error.HTTPError as exc:
        # Record only status/field names, never raw ENV, tokens or error values.
        fields=[]
        try:
            errors=json.loads(exc.read()).get('errors',{})
            if isinstance(errors,dict):fields=sorted(k for k in errors if k in (data or {}))
        except (ValueError,AttributeError):pass
        save('revision-api-refusal',{'method':method,'status':exc.code,'validationFields':fields})
        raise

def command(mode):
    script='helper' if mode=='build' else 'revisions'
    url='https://raw.githubusercontent.com/'+os.environ['GITHUB_REPOSITORY']+'/'+sha+'/bench/'+script+'.sh'
    helper_id=image.split(':')[1][:12]
    args=(helper_id+' --project-directory . build') if mode=='build' else (mode+' '+helper_id+' --project-directory .')
    cmd='curl -fsSL '+url+' -o /tmp/vh && sh /tmp/vh '+args
    assert len(cmd)<=255,'Custom command too long'
    return cmd

def runtime(app):
    ids=subprocess.check_output(['docker','ps','-aq','--filter','name='+app],text=True,timeout=10).split()
    rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True,timeout=10)) if ids else []
    return [{'id':x['Id'],'service':x['Config']['Labels'].get('com.docker.compose.service'),
        'project':x['Config']['Labels'].get('com.docker.compose.project'),
        'image':x['Image'],'state':x['State']['Status'],'exitCode':x['State']['ExitCode'],
        'restartPolicy':x['HostConfig']['RestartPolicy'],
        'memory':x['HostConfig']['Memory'],'nanoCpus':x['HostConfig']['NanoCpus'],
        'ports':x['HostConfig']['PortBindings'],
        'mounts':sorted([(m.get('Name'),m['Destination'],m['RW']) for m in x['Mounts']])} for x in rows]

def http(host):
    for _ in range(20):
        try:
            with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1',headers={'Host':host}),timeout=3) as r:
                return json.load(r)
        except Exception:time.sleep(1)
    raise RuntimeError('HTTP did not become healthy')

def deploy(app,action='start'):
    response=api('/applications/'+app+'/'+action,'POST')
    deployment=response['deployment_uuid']
    for _ in range(150):
        d=api('/deployments/'+deployment)
        if d.get('status') in ['finished','failed','cancelled','canceled']:
            receipt={k:d.get(k) for k in ['deployment_uuid','status','commit','created_at','updated_at']}
            logs=d.get('logs',[])
            if isinstance(logs,str):
                try:logs=json.loads(logs)
                except json.JSONDecodeError:logs=[]
            if receipt['status']!='finished':
                messages=[x.get('output','') for x in logs if isinstance(x,dict)]
                receipt['syntheticFailureMessages']=[x for x in messages if 'error' in x.lower() or 'failed' in x.lower()][-8:]
            save('revision-deployment-'+deployment,receipt)
            return receipt
        time.sleep(2)
    raise RuntimeError('Deployment outcome unknown; no retry/recovery')

def fresh_identity(app):
    d=api('/applications/'+app)
    checked=identity_checks(d,app,os.environ['GITHUB_REPOSITORY'],branch,sha)
    save('revision-identity-'+app,{'checks':checked})
    assert all(checked.values()),'Exact provider source identity mismatch: '+','.join(k for k,v in checked.items() if not v)
    return {k:d[k] for k in ['uuid','git_repository','git_branch','git_commit_sha','build_pack']}

def stop(app):
    fresh_identity(app)
    before=runtime(app)
    assert len(before)<=2,'Unexpected runtime size; stop scenario not bounded'
    evidence={'application':app,'timeoutSeconds':120,'before':before,'history':[]}
    name='revision-stop-'+app+'-'+str(len(result['steps']))
    save(name+'-observation',evidence)
    api('/applications/'+app+'/stop','POST',{'docker_cleanup':False})
    evidence['stopAcknowledged']=True
    save(name+'-observation',evidence)
    def record(elapsed,rows):
        evidence['elapsedSeconds']=round(elapsed,3)
        evidence['runtime']=rows[:32]
        state=[{'id':x['id'],'service':x['service'],'state':x['state']} for x in rows[:32]]
        if not evidence['history'] or evidence['history'][-1]['runtime']!=state:
            evidence['history'].append({'elapsedSeconds':round(elapsed,3),'runtime':state})
        assert len(evidence['history'])<=125,'Unexpected runtime churn'
        save(name+'-observation',evidence)
    # Provider stops services sequentially, each with a30s default grace period.
    # Allow2*30s plus bounded queue/transport overhead; never treat ACK as removal.
    observed=wait_for_removal(lambda:runtime(app),observe=record)
    checkpoint(name,{'application':app,'runtime':observed,'containersRemoved':True,
                     'elapsedSeconds':evidence['elapsedSeconds']})
    return observed

def no_writers():
    # Read-only engine evidence across ALL apps on this disposable host.
    for volume in volume_names:
        subprocess.run(['docker','volume','inspect',volume],check=True,stdout=subprocess.DEVNULL)
        ids=subprocess.check_output(['docker','ps','-aq','--filter','volume='+volume],text=True).split()
        assert not ids,'Shared volume still has a container, including stopped; no launch authorized'

def work(app):return pathlib.Path('/data/coolify/applications')/app
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def artifact(app,kind):return work(app)/'.vibenest-revision'/(kind+'.json')

def check_mounts(rows):
    check_runtime(rows,prefix)

def images(rows):return {x['service']:x['image'] for x in rows}

def create(name,domain,mode):
    body={'name':name,'project_uuid':project,'environment_name':'production','server_uuid':server['uuid'],
        'git_repository':repo,'git_branch':branch,'git_commit_sha':sha,'build_pack':'dockercompose',
        'ports_exposes':'3000','docker_compose_location':'/docker-compose.yaml',
        'docker_compose_domains':[{'name':'web','domain':'http://'+domain+':3000'}],
        'docker_compose_custom_build_command':command('build'),'docker_compose_custom_start_command':command(mode),
        'is_preserve_repository_enabled':True,'is_auto_deploy_enabled':False,
        'is_preview_deployments_enabled':False,'instant_deploy':False}
    app=api('/applications/public','POST',body)['uuid']
    api('/applications/'+app+'/envs','POST',{'key':'VN_CONTRACT_VOLUME_PREFIX','value':prefix,'is_literal':True,'is_preview':False,'is_buildtime':False})
    assert runtime(app)==[],'Create unexpectedly launched runtime'
    fresh_identity(app)  # Check source anchor before spending a build.
    return app

try:
    stage('provider-setup')
    version=api('/version');assert version=='4.7.5' or version=={'version':'4.7.5'}
    server=api('/servers')[0]
    project=api('/projects','POST',{'name':'Native revision feasibility'})['uuid']
    stage('old-create-and-identity')
    old=create('retained-old','old.contract.localhost','seed')
    stage('old-seed-deploy')
    assert deploy(old)['status']=='finished','Old baseline deploy failed'
    stage('old-runtime-mounts-and-limits')
    old_runtime=runtime(old)
    save('revision-old-runtime-before-checks',{'count':len(old_runtime),'runtime':old_runtime[:32]})
    check_mounts(old_runtime)
    stage('old-http')
    baseline=http('old.contract.localhost');assert baseline['redis']=='+PONG'
    stage('old-artifact-hashes')
    retained_hash=digest(artifact(old,'retained'))
    old_config_hash=digest(work(old)/'docker-compose.yaml')
    stage('old-post-deploy-identity')
    checkpoint('revision-old-baseline',{'identity':fresh_identity(old),'runtime':old_runtime,'http':baseline,'retainedHash':retained_hash})

    stage('candidate-create-and-prepare')
    candidate=create('staged-candidate','candidate.contract.localhost','prepare')
    assert deploy(candidate)['status']=='finished','Prepare-only native deploy failed'
    assert runtime(candidate)==[],'Prepare-only started candidate runtime'
    assert runtime(old)==old_runtime and http('old.contract.localhost')==baseline
    assert digest(artifact(old,'retained'))==retained_hash and digest(work(old)/'docker-compose.yaml')==old_config_hash
    prepared=json.loads(artifact(candidate,'prepared').read_text())
    assert {v['name'] for v in prepared['volumes'].values()}==set(volume_names)
    assert all(v['external'] is True for v in prepared['volumes'].values())
    prepared_hash=digest(artifact(candidate,'prepared'))
    prepared_images={k:v['image'] for k,v in prepared['services'].items()}
    # A mutable upstream Redis tag must not silently widen the data-compatibility
    # assumption of this synthetic recovery experiment.
    assert prepared_images['redis']==images(old_runtime)['redis'],'Redis image changed; compatibility unproven'
    checkpoint('revision-candidate-prepared',{'identity':fresh_identity(candidate),'runtime':runtime(candidate),'preparedHash':prepared_hash,
        'images':prepared_images,'volumes':volume_names,'oldUntouched':True})

    stage('old-remove-and-candidate-activate')
    stop(old);no_writers()
    assert digest(artifact(candidate,'prepared'))==prepared_hash
    fresh_identity(candidate)
    api('/applications/'+candidate,'PATCH',{'docker_compose_custom_build_command':'true','docker_compose_custom_start_command':command('activate')})
    assert deploy(candidate)['status']=='finished','Candidate activation failed'
    active=runtime(candidate);check_mounts(active);assert images(active)==prepared_images
    candidate_http=http('candidate.contract.localhost');assert candidate_http['marker']==baseline['marker']
    checkpoint('revision-candidate-active',{'runtime':active,'http':candidate_http,'oldRuntime':runtime(old)})

    # Explicit baseline restore for the second scenario. Never in an exception handler.
    stage('candidate-remove-and-old-exact-resume')
    stop(candidate);no_writers();fresh_identity(old)
    assert digest(artifact(old,'retained'))==retained_hash
    api('/applications/'+old,'PATCH',{'docker_compose_custom_build_command':'true','docker_compose_custom_start_command':command('resume')})
    assert deploy(old,'restart')['status']=='finished','Exact old resume failed'
    resumed=runtime(old);check_mounts(resumed);assert images(resumed)==images(old_runtime)
    resume_http=http('old.contract.localhost');assert resume_http['marker']==baseline['marker']
    checkpoint('revision-old-resumed',{'runtime':resumed,'http':resume_http,'retainedHash':digest(artifact(old,'retained'))})

    # Known synthetic compatibility: same web source and Redis digest, no schema migrations.
    stage('old-remove-and-candidate-fault')
    stop(old);no_writers();fresh_identity(candidate)
    assert digest(artifact(candidate,'prepared'))==prepared_hash
    api('/applications/'+candidate,'PATCH',{'docker_compose_custom_start_command':command('fault')})
    failed=deploy(candidate);assert failed['status']=='failed','Expected fault not observed'
    failed_runtime=runtime(candidate);check_mounts(failed_runtime)
    assert any(x['service']=='web' and x['state']=='exited' and x['exitCode']==42 for x in failed_runtime)
    checkpoint('revision-candidate-failed',{'deployment':failed,'runtime':failed_runtime,'retainedHash':digest(artifact(old,'retained'))})

    # Separate, deliberate synthetic recovery after exact outcome + no-writer proof.
    # Platform security/owner admission is NOT emulated or certified by this harness.
    stage('candidate-remove-and-explicit-old-recovery')
    stop(candidate);no_writers();identity=fresh_identity(old)
    assert digest(artifact(old,'retained'))==retained_hash
    assert deploy(old,'restart')['status']=='finished','Gated fixture recovery failed'
    recovered=runtime(old);check_mounts(recovered);assert images(recovered)==images(old_runtime)
    recovered_http=http('old.contract.localhost')
    assert recovered_http['marker']==baseline['marker'] and recovered_http['boots']==resume_http['boots']+1
    checkpoint('revision-old-recovered',{'identity':identity,'runtime':recovered,'http':recovered_http,'retainedHash':digest(artifact(old,'retained'))})
    stage('writer-trace-verification')
    time.sleep(1)
    stream.terminate();stream.wait(timeout=5);event_thread.join(timeout=5)
    projects={x['project'] for x in old_runtime+active}
    assert not event_errors and not event_thread.is_alive(),'Incomplete Docker event stream'
    assert writer_trace(events,projects,{x['id'] for x in old_runtime},{x['id'] for x in recovered}), 'Overlapping writers or incomplete trace'
    result['singleWriterTrace']='passed_in_serialized_disposable_fixture_only'
    result['nativePrimitiveFeasibility']='passed_for_synthetic_fixture_only'
except Exception as exc:
    result['nativePrimitiveFeasibility']='failed_or_unproven'
    result['failureType']=type(exc).__name__
    raise
finally:
    if stream.poll() is None:stream.terminate();stream.wait(timeout=5)
    event_thread.join(timeout=5)
    projects={x['project'] for x in locals().get('old_runtime',[])+locals().get('active',[])}
    save('revision-lifecycle-events',{'errors':event_errors,'events':[e for e in events if e['project'] in projects]})
    save('native-revisions-result',result)
