import json, pathlib, subprocess
p=pathlib.Path('evidence');p.mkdir(exist_ok=True)
r=subprocess.run(['docker','ps','-a','--format','{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}'],text=True,capture_output=True)
(p/'containers.txt').write_text(r.stdout)
script='''$files=glob("/var/www/html/storage/logs/laravel*.log"); foreach($files as $file) { foreach(file($file) as $line) { if(str_contains($line,".ERROR:")) echo explode('{"exception"',$line)[0]."\\n"; } }'''
r=subprocess.run(['docker','exec','coolify','php','-r',script],text=True,capture_output=True)
errors=r.stdout
envfile=pathlib.Path('/data/coolify/source/.env')
if envfile.exists():
    for line in envfile.read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1)
            if len(value)>8:errors=errors.replace(value,'[redacted]')
tokenfile=pathlib.Path('/tmp/coolify-contract-token')
if tokenfile.exists():errors=errors.replace(tokenfile.read_text(),'[redacted]')
(p/'provider-error-summary.txt').write_text(errors[-8000:])
# Never export env files, tokens, raw inspect Env, repository copies or database dumps.
