import hashlib, json, os, pathlib, subprocess, time, urllib.request, urllib.error
from lifecycle_assertions import classify_case

assert os.environ.get('GITHUB_ACTIONS')=='true'
E=pathlib.Path('evidence');E.mkdir(exist_ok=True)
token=pathlib.Path('/tmp/coolify-contract-token').read_text()
image=pathlib.Path('/tmp/coolify-contract-helper').read_text()
def api(path,method='GET',data=None):
    request=urllib.request.Request('http://127.0.0.1:8000/api/v1'+path,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'},data=json.dumps(data).encode() if data is not None else None)
    try:
        with urllib.request.urlopen(request,timeout=30) as r:
            raw=r.read().decode()
            try:return json.loads(raw)
            except json.JSONDecodeError:
                if path=='/version':return raw.strip()
                raise
    except urllib.error.HTTPError as e:
        raise RuntimeError(str(e.code)+' '+e.read().decode()[:1500]) from None
def save(name,value):
    (E/(name+'.json')).write_text(json.dumps(value,indent=2))
def deploy(action='start'):
    result=api('/applications/'+app+'/'+action,'POST')
    deployment=result['deployment_uuid']
    for i in range(150):
        d=api('/deployments/'+deployment)
        status=d.get('status')
        if status in ['finished','failed','cancelled','canceled']:
            # Fixture has no secret ENV. Still exclude raw provider logs from public evidence.
            out={k:d.get(k) for k in ['deployment_uuid','status','commit','created_at','updated_at']}
            save('deployment-'+deployment,out)
            logs=d.get('logs','')
            if isinstance(logs,str):
                try:logs=json.loads(logs)
                except Exception:logs=[]
            messages=[x.get('output','') for x in logs if isinstance(x,dict)]
            out['preparedMarkerObserved']=any(x.strip()=='VIBENEST_CONTRACT_PREPARED_NO_CANDIDATE_WRITES' for x in messages)
            if status!='finished':
                logs=d.get('logs','')
                if isinstance(logs,str):
                    try:logs=json.loads(logs)
                    except Exception: logs=[]
                messages=[x.get('output','') for x in logs if isinstance(x,dict)]
                save('failure-messages',[x for x in messages if 'error' in x.lower() or 'failed' in x.lower()][-12:])
            return out
        time.sleep(3)
    raise RuntimeError('Deployment timeout')
def runtime():
    ids=subprocess.check_output(['docker','ps','-aq','--filter','name='+app],text=True).split()
    all_=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True)) if ids else []
    return [{'id':x['Id'],'imageId':x['Image'],'service':x['Config']['Labels'].get('com.docker.compose.service'),'state':x['State']['Status'],'exitCode':x['State']['ExitCode'],'memory':x['HostConfig']['Memory'],'nanoCpus':x['HostConfig']['NanoCpus'],'ports':x['HostConfig']['PortBindings'],'mounts':sorted(x['Mounts'],key=lambda m:m['Destination']),'labels':x['Config']['Labels'],'networks':sorted(x['NetworkSettings']['Networks'])} for x in all_]
def http(tries=30):
    for i in range(tries):
        try:
            r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1',headers={'Host':'contract.localhost'}),timeout=3)
            return json.load(r)
        except Exception:time.sleep(2)
    raise RuntimeError('Proxy route not reachable')
server=api('/servers')[0]
version=api('/version')
assert version == '4.7.5' or version == {'version':'4.7.5'}, ('Unexpected provider version',version)
project=api('/projects','POST',{'name':'Isolated contract'})['uuid']
sha=os.environ['GITHUB_SHA'];repo='https://github.com/'+os.environ['GITHUB_REPOSITORY']
branch=os.environ['GITHUB_REF_NAME']
url='https://raw.githubusercontent.com/'+os.environ['GITHUB_REPOSITORY']+'/'+sha+'/bench/helper.sh'
def command(mode):
    # Coolify 4.5.3 stores custom commands in varchar(255). The local image's
    # unambiguous short ID avoids a mutable tag; full identity is in evidence.
    value='curl -fsSL '+url+' -o /tmp/vh && sh /tmp/vh '+mode+' '+image.split(':')[1][:12]+' --project-directory .'
    assert len(value)<=255, 'Provider custom-command size limit'
    return value
body={'name':'compose-contract','project_uuid':project,'environment_name':'production','server_uuid':server['uuid'],'git_repository':repo,'git_branch':branch,'git_commit_sha':sha,'build_pack':'dockercompose','ports_exposes':'3000','docker_compose_location':'/docker-compose.yaml','docker_compose_domains':[{'name':'web','domain':'http://contract.localhost:3000'}],'docker_compose_custom_build_command':command('build'),'docker_compose_custom_start_command':command('start'),'is_preserve_repository_enabled':True,'is_auto_deploy_enabled':False,'is_preview_deployments_enabled':False,'instant_deploy':False}
app=api('/applications/public','POST',body)['uuid']
pathlib.Path('/tmp/coolify-contract-app').write_text(app)
save('identity',{'providerVersion':version,'providerHosting':'disposable-self-hosted','productionCloudArtifactParity':'unknown','sourceSha':sha,'application':app,'helperImage':image})
assert deploy()['status']=='finished','Initial deploy failed'
first=runtime();save('initial-runtime',first)
for service,memory,cpu in [('web',384*1024*1024,375000000),('redis',128*1024*1024,125000000)]:
    x=next(x for x in first if x['service']==service and x['state']=='running')
    assert x['memory']==memory and x['nanoCpus']==cpu,(service,'limits')
    assert not x['ports'],(service,'host ports')
    assert any(m['Type']=='volume' and m['RW'] for m in x['mounts'])
first_http=http();save('initial-http',first_http);assert first_http['redis']=='+PONG'
def assert_same_runtime(after):
    for name in ['web','redis']:
        previous=next(x for x in first if x['service']==name and x['state']=='running')
        current=next(x for x in after if x['service']==name and x['state']=='running')
        for key in ['memory','nanoCpus','ports','networks']:
            assert previous[key]==current[key],(name,key,'changed after lifecycle')
        mounts=lambda x: sorted((m['Name'],m['Destination'],m['RW']) for m in x['mounts'] if m['Type']=='volume')
        assert mounts(previous)==mounts(current),(name,'volume identity changed')
work=pathlib.Path('/data/coolify/applications')/app
effective=work/'.vibenest-final/effective.json'
assert effective.exists(),'Effective configuration did not survive provider finalization'
config=json.loads(effective.read_text());save('saved-config-shape',{'services':list(config['services']),'volumes':config.get('volumes'),'limits':{k:{q:v.get(q) for q in ['mem_limit','cpus','ports','image','networks','labels']} for k,v in config['services'].items()}})
assert deploy('restart')['status']=='finished','Restart failed'
second=http();save('restart-http',second);second_runtime=runtime();save('restart-runtime',second_runtime);assert second['marker']==first_http['marker'];assert_same_runtime(second_runtime)
assert deploy()['status']=='finished','Redeploy failed'
third=http();save('redeploy-http',third);third_runtime=runtime();save('redeploy-runtime',third_runtime);assert third['marker']==first_http['marker'];assert_same_runtime(third_runtime)
def config_fingerprints():
    # Synthetic instance only. Export hashes, never runtime ENV or config content.
    return {name:hashlib.sha256((work/name).read_bytes()).hexdigest() if (work/name).is_file() else None
            for name in ['docker-compose.yaml','.env','.vibenest-final/effective.json']}

def negative_case(name, start_command):
    before=runtime();before_http=http();config_before=config_fingerprints()
    since=int(time.time())
    api('/applications/'+app,'PATCH',{'docker_compose_custom_start_command':start_command})
    result=deploy();after=runtime()
    try:after_http=http(tries=3)
    except RuntimeError:after_http=None
    project=before[0]['labels']['com.docker.compose.project']
    events=subprocess.check_output(['docker','events','--since',str(since),'--until',str(int(time.time())),
        '--filter','type=container','--filter','label=com.docker.compose.project='+project,'--format','{{json .}}'],text=True)
    sanitized=[]
    for line in events.splitlines():
        e=json.loads(line);actor=e.get('Actor',{});a=actor.get('Attributes',{})
        sanitized.append({'timeNano':e.get('timeNano'),'action':e.get('Action'), 'id':actor.get('ID'),
                          'service':a.get('com.docker.compose.service'),'exitCode':a.get('exitCode')})
    config_after=config_fingerprints()
    verdict=classify_case(before,after,before_http,after_http,config_before,config_after)
    verdict.update({'deployment':result,'expectedFailureObserved':result['status']=='failed',
        'candidateExitBeforeWritesObserved':any(x['service']=='web' and x['state']=='exited' and x['exitCode']==42 for x in after),
        'fallbackAttempted':False,'afterWriteRecoveryTested':False,'singleWriterAcceptance':'not_certified'})
    save(name,{'before':before,'after':after,'beforeHttp':before_http,'afterHttp':after_http,
               'configBefore':config_before,'configAfter':config_after,'events':sanitized,'verdict':verdict})
    return verdict

# Both cases run even when the first exposes the known destructive ordering.
refused=negative_case('refused-start','false')
# Deliberate reset of this synthetic baseline, NOT product fallback/recovery.
api('/applications/'+app,'PATCH',{'docker_compose_custom_start_command':command('start')})
assert deploy()['status']=='finished','Synthetic baseline reset failed'
assert http()['marker']==first_http['marker'],'Baseline reset lost persisted fixture data'
failed=negative_case('failed-candidate-start',command('failstart'))
save('contract-result',{'preparedConfigPersists':True,'initialLimitsAndRouting':True,
    'restartAndRedeployPersistence':True,'preEffectRefusal':refused,'postPrepareStartFailure':failed,
    'productionEnablementAllowed':False,'appDirectPrivateSourceTested':False,
    'limitation':'Native provider regression only; gated recovery, Cloud artifact parity and private artifact integration untested.'})
assert refused['expectedFailureObserved'] and refused['preserved'],'Pre-effect refusal did not preserve the prior runtime/config/HTTP'
assert failed['deployment']['preparedMarkerObserved'] and failed['candidateExitBeforeWritesObserved'],'Start fault did not reach the intended post-prepare phase'
assert failed['preserved'],'Candidate start failure did not preserve or restore the prior runtime'
