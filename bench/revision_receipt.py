"""Terminal identity is durable before optional, bounded log diagnostics."""
import json

TERMINAL={'finished','failed','cancelled','canceled'}

def failure_messages(logs):
    if isinstance(logs,str):
        if len(logs)>131072:return []
        try:logs=json.loads(logs)
        except (ValueError,RecursionError):return []
    # Maps, null and scalars are not log-entry lists. Never dump their contents.
    if not isinstance(logs,list):return []
    messages=[]
    for entry in logs[-256:]:
        if not isinstance(entry,dict):continue
        value=entry.get('output')
        if not isinstance(value,str):continue
        value=value[:2000]
        if 'error' in value.lower() or 'failed' in value.lower():messages.append(value)
    return messages[-8:]

def record_terminal(deployment,details,write):
    status=details.get('status')
    if status not in TERMINAL:raise ValueError('Not a terminal provider result')
    receipt={k:details.get(k) for k in ['status','commit','created_at','updated_at']}
    receipt['deployment_uuid']=deployment
    receipt['reportedDeploymentUuid']=details.get('deployment_uuid')
    name='revision-deployment-'+deployment
    # The known UUID comes from the accepted dispatch; save even if optional logs
    # are null/malformed or a future diagnostic parser throws unexpectedly.
    write(name,dict(receipt))
    if receipt['reportedDeploymentUuid'] not in (None,deployment):
        raise ValueError('Provider deployment receipt identity mismatch')
    try:
        if status!='finished':receipt['syntheticFailureMessages']=failure_messages(details.get('logs'))
    except Exception:
        receipt['logDiagnostics']='unavailable'
    write(name,dict(receipt))
    return receipt
