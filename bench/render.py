"""Contract prototype only. No production artifact authorization is implemented here."""
import json, sys
assert sys.argv[1] in {'build','start','failstart'}, 'Unknown fixture mode'
doc=json.load(sys.stdin)
assert set(doc['services'])=={'web','redis'}, 'Unexpected service set'
for name,ram,cpu in [('web',384,0.375),('redis',128,0.125)]:
    s=doc['services'][name]
    if sys.argv[1]=='build':
        # Coolify creates runtime .env only after the build. Never copy build
        # credentials into the source context just to satisfy this runtime path.
        s.pop('env_file',None)
    s.pop('ports',None)
    s['mem_limit']=str(ram*1024*1024)
    s['cpus']=str(cpu)
    s.setdefault('deploy',{}).setdefault('resources',{})['limits']={'memory':str(ram*1024*1024),'cpus':str(cpu)}
    assert all(v['type']=='volume' for v in s.get('volumes',[])), 'Unexpected bind mount'
if sys.argv[1]=='failstart':
    # Synthetic fault only: no process from server.mjs runs, no state is opened,
    # and restart policy cannot turn the fault into an unbounded crash loop.
    web=doc['services']['web']
    web['entrypoint']=['/bin/sh','-c','echo VIBENEST_CONTRACT_CANDIDATE_EXIT_BEFORE_WRITES; exit 42']
    web['command']=[]
    web['restart']='no'
    web.get('deploy',{}).pop('restart_policy',None)
json.dump(doc,sys.stdout,separators=(',',':'))
