import json, os, pathlib, subprocess, time, urllib.request, urllib.error

assert os.environ.get('GITHUB_ACTIONS')=='true'
E=pathlib.Path('evidence');E.mkdir(exist_ok=True)
token=pathlib.Path('/tmp/coolify-contract-token').read_text()
image=pathlib.Path('/tmp/coolify-contract-helper').read_text()
def api(path,method='GET',data=None):
    request=urllib.request.Request('http://127.0.0.1:8000/api/v1'+path,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'},data=json.dumps(data).encode() if data is not None else None)
    try:
        with urllib.request.urlopen(request,timeout=30) as r:return json.load(r)
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
    return [{'id':x['Id'],'service':x['Config']['Labels'].get('com.docker.compose.service'),'state':x['State']['Status'],'memory':x['HostConfig']['Memory'],'nanoCpus':x['HostConfig']['NanoCpus'],'ports':x['HostConfig']['PortBindings'],'mounts':x['Mounts'],'labels':x['Config']['Labels'],'networks':list(x['NetworkSettings']['Networks'])} for x in all_]
def http():
    for i in range(30):
        try:
            r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1',headers={'Host':'contract.localhost'}),timeout=3)
            return json.load(r)
        except Exception:time.sleep(2)
    raise RuntimeError('Proxy route not reachable')
server=api('/servers')[0]
project=api('/projects','POST',{'name':'Isolated contract'})['uuid']
sha=os.environ['GITHUB_SHA'];repo='https://github.com/'+os.environ['GITHUB_REPOSITORY']
url='https://raw.githubusercontent.com/'+os.environ['GITHUB_REPOSITORY']+'/'+sha+'/bench/helper.sh'
def command(mode): return 'curl -fsSL '+url+' -o /tmp/vibenest-contract-helper.sh && sh /tmp/vibenest-contract-helper.sh '+mode+' '+image+' --project-directory .'
body={'name':'compose-contract','project_uuid':project,'environment_name':'production','server_uuid':server['uuid'],'git_repository':repo,'git_branch':'main','git_commit_sha':sha,'build_pack':'dockercompose','ports_exposes':'3000','docker_compose_location':'/docker-compose.yaml','docker_compose_domains':[{'name':'web','domain':'http://contract.localhost:3000'}],'docker_compose_custom_build_command':command('build'),'docker_compose_custom_start_command':command('start'),'is_preserve_repository_enabled':True,'is_auto_deploy_enabled':False,'is_preview_deployments_enabled':False,'instant_deploy':False}
app=api('/applications/public','POST',body)['uuid']
pathlib.Path('/tmp/coolify-contract-app').write_text(app)
save('identity',{'providerVersion':'4.5.3','sourceSha':sha,'application':app,'helperImage':image})
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
# Test the mandatory old-revision preservation contract without touching production.
api('/applications/'+app,'PATCH',{'docker_compose_custom_start_command':'false'})
result=deploy();save('refused-start',result)
after=runtime();save('refused-start-runtime',after)
preserved=any(x['service']=='web' and x['state']=='running' for x in after)
save('contract-result',{'preparedConfigPersists':True,'initialLimitsAndRouting':True,'restartAndRedeployPersistence':True,'previousRevisionPreservedOnStartRefusal':preserved,'productionEnablementAllowed':preserved,'appDirectPrivateSourceTested':False})
assert preserved,'Coolify stopped the previous revision before the custom start refusal'
