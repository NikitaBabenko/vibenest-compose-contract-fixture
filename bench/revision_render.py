"""Synthetic revision artifact preparation. Not a production authorization service."""
import copy
import json
import pathlib
import re
import subprocess
import sys

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')

def prepare(doc, mode):
    if mode not in {'seed', 'prepare'}:
        raise ValueError('Unknown preparation mode')
    doc=copy.deepcopy(doc)
    if set(doc.get('services',{}))!={'web','redis'}:
        raise ValueError('Unexpected services')
    prefix=doc['services']['web'].get('environment',{}).get('VN_CONTRACT_VOLUME_PREFIX','')
    if not re.fullmatch(r'vnrev[0-9]{1,20}',prefix):
        raise ValueError('Invalid synthetic shared volume namespace')
    doc['volumes']={}
    for name,target in [('web','/app/data'),('redis','/data')]:
        service=doc['services'][name]
        mounts=service.get('volumes',[])
        if len(mounts)!=1 or mounts[0].get('type')!='volume' or mounts[0].get('target')!=target:
            raise ValueError('Unexpected named mount')
        key='shared-'+name
        mounts[0]['source']=key
        doc['volumes'][key]={'name':prefix+'-'+name,'external':mode!='seed'}
        service.pop('env_file',None)  # docker compose config already resolves runtime ENV
    return doc

def pin(doc, image_ids):
    doc=copy.deepcopy(doc)
    names=sorted(doc['services'])
    if len(image_ids)!=len(names) or not all(DIGEST.fullmatch(x) for x in image_ids):
        raise ValueError('Missing immutable image identity')
    for name,id_ in zip(names,image_ids):
        service=doc['services'][name]
        if 'env_file' in service:
            raise ValueError('Unresolved runtime environment')
        service['image']=id_
        service.pop('build',None)
        service['pull_policy']='never'
    return doc

def retain(doc):
    doc=copy.deepcopy(doc)
    for volume in doc['volumes'].values():
        volume['external']=True
    return doc

def fault(doc):
    doc=copy.deepcopy(doc)
    web=doc['services']['web']
    web['entrypoint']=['/bin/sh','-c','echo VIBENEST_CONTRACT_CANDIDATE_EXIT_BEFORE_WRITES; exit 42']
    web['command']=[];web['restart']='no'
    web.get('deploy',{}).pop('restart_policy',None)
    return doc

def main():
    mode=sys.argv[1]
    if mode=='pin':
        doc=json.loads(sys.stdin.readline())
        doc=pin(doc,[s.strip() for s in sys.stdin if s.strip()])
    else:
        doc=json.load(sys.stdin)
        if mode in {'seed','prepare'}:
            # Reuse the existing sanitizer/limits contract; no original YAML start.
            rendered=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('render.py')),'start'],
                                    input=json.dumps(doc),text=True,capture_output=True,check=True)
            doc=prepare(json.loads(rendered.stdout),mode)
        elif mode=='images':
            for name in sorted(doc['services']):
                ref=doc['services'][name]['image']
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/@:-]*',ref):
                    raise ValueError('Invalid image reference')
                print(ref)
            return
        elif mode=='retain':doc=retain(doc)
        elif mode=='fault':doc=fault(doc)
        else:raise ValueError('Unknown revision mode')
    json.dump(doc,sys.stdout,separators=(',',':'))

if __name__=='__main__':main()
