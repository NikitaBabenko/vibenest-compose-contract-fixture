import base64, json, os, pathlib, secrets, subprocess, time, urllib.request

assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Disposable Actions runner only'
root=pathlib.Path('/data/coolify')
def run(args,**kw): return subprocess.run(args,check=True,**kw)
run(['sudo','mkdir','-p',*[str(root/x) for x in ['source','ssh/keys','ssh/mux','applications','databases','services','backups','images']]])
run(['sudo','chown','-R',f'{os.getuid()}:{os.getgid()}',str(root)])
for file in ['docker-compose.yml','docker-compose.prod.yml']:
    (root/'source'/file).write_bytes(urllib.request.urlopen('https://raw.githubusercontent.com/coollabsio/coolify/v4.5.3/'+file,timeout=30).read())
env={'LATEST_IMAGE':'4.5.3','APP_ID':secrets.token_hex(16),'APP_KEY':'base64:'+base64.b64encode(secrets.token_bytes(32)).decode(),
     'DB_USERNAME':'coolify','DB_PASSWORD':secrets.token_hex(24),'REDIS_PASSWORD':secrets.token_hex(24),
     'PUSHER_APP_ID':secrets.token_hex(12),'PUSHER_APP_KEY':secrets.token_hex(24),'PUSHER_APP_SECRET':secrets.token_hex(24),
     'ROOT_USERNAME':'ContractAdmin'}
for key,val in env.items():
    if any(x in key for x in ['PASSWORD','SECRET','KEY']): print('::add-mask::'+val,flush=True)
(root/'source/.env').write_text('\n'.join(f'{k}={v}' for k,v in env.items())+'\n')
key=root/'ssh/keys/id.root@host.docker.internal'
run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
run(['sudo','mkdir','-p','/root/.ssh'])
run(['sudo','cp',str(key)+'.pub','/root/.ssh/authorized_keys'])
run(['sudo','chmod','600','/root/.ssh/authorized_keys'])
run(['sudo','systemctl','start','ssh'])
run(['sudo','chown','-R','9999:root',str(root/'ssh')])
run(['docker','network','create','coolify'])
run(['docker','compose','--env-file',str(root/'source/.env'),'-f',str(root/'source/docker-compose.yml'),'-f',str(root/'source/docker-compose.prod.yml'),'up','-d'])
for i in range(120):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3) as r:
            if r.status==200: break
    except Exception: pass
    time.sleep(3)
else: raise RuntimeError('Coolify bootstrap health timeout')
# Health can become available before the initial seed completes.
prefix='require "vendor/autoload.php"; $app=require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); '
probe=prefix+'if (!App\\Models\\Team::where("id",0)->exists() || !App\\Models\\InstanceSettings::first() || !App\\Models\\Server::where("id",0)->exists()) exit(2); echo "ready";'
for i in range(60):
    r=subprocess.run(['docker','exec','coolify','php','-r',probe],capture_output=True,text=True)
    if r.returncode==0 and r.stdout.endswith('ready'):break
    time.sleep(3)
else:
    detail=r.stdout+r.stderr
    for key,val in env.items():
        if len(val)>8:detail=detail.replace(val,'[redacted]')
    raise RuntimeError('Initial seed not ready: '+detail[-2000:])
# Bootstrap only this disposable instance; never used against production.
php="""$settings=App\\Models\\InstanceSettings::first(); $settings->update(['is_api_enabled'=>true]);
$user=App\\Models\\User::find(0); if (!$user) { $user=(new App\\Models\\User)->forceFill(['id'=>0,'name'=>'ContractAdmin','email'=>'contract@example.invalid','password'=>Illuminate\\Support\\Facades\\Hash::make(bin2hex(random_bytes(32)))]); $user->save(); }
$token=$user->createToken('isolated-contract',['root'],null,0);
$token->accessToken->team_id=0; $token->accessToken->save(); echo $token->plainTextToken;"""
r=subprocess.run(['docker','exec','coolify','php','-r',prefix+'try {'+php+'} catch (Throwable $e) { fwrite(STDERR,get_class($e)." at ".$e->getFile().":".$e->getLine()."\\n"); exit(3); }'],capture_output=True,text=True)
if r.returncode:
    raise RuntimeError('Ephemeral API bootstrap failed: '+r.stderr[-2000:])
token=r.stdout.strip().splitlines()[-1]
assert '|' in token, 'Ephemeral token bootstrap failed'
print('::add-mask::'+token,flush=True)
pathlib.Path('/tmp/coolify-contract-token').write_text(token)
pathlib.Path('/tmp/coolify-contract-token').chmod(0o600)
run(['docker','build','-f','bench/helper.Dockerfile','-t','vibenest-contract-helper:local','.'])
image=subprocess.check_output(['docker','image','inspect','vibenest-contract-helper:local','--format','{{.Id}}'],text=True).strip()
pathlib.Path('/tmp/coolify-contract-helper').write_text(image)
print('Disposable Coolify 4.5.3 ready')
