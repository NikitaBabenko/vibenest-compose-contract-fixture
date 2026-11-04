"""Contract prototype only. No production artifact authorization is implemented here."""
import json, sys
doc=json.load(sys.stdin)
assert set(doc['services'])=={'web','redis'}, 'Unexpected service set'
for name,ram,cpu in [('web',384,0.375),('redis',128,0.125)]:
    s=doc['services'][name]
    s.pop('ports',None)
    s['mem_limit']=str(ram*1024*1024)
    s['cpus']=str(cpu)
    s.setdefault('deploy',{}).setdefault('resources',{})['limits']={'memory':str(ram*1024*1024),'cpus':str(cpu)}
    assert all(v['type']=='volume' for v in s.get('volumes',[])), 'Unexpected bind mount'
json.dump(doc,sys.stdout,separators=(',',':'))
