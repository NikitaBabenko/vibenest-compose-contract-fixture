def writer_trace(events, projects, baseline_ids, final_ids):
    """Check the complete fixture stream, not a pair of snapshots. Unknown fails closed."""
    active={};seen=set()
    for event in events:
        if event['project'] not in projects:
            continue
        key=event['service'];id_=event['id'];action=event['action']
        if key not in {'web','redis'}:
            return False
        writers=active.setdefault(key,set())
        if action=='start':
            writers.add(id_);seen.add(id_)
            if len(writers)>1:return False
        elif action in {'die','destroy'}:
            writers.discard(id_)
    return bool(baseline_ids and baseline_ids<=seen and set().union(*active.values())==final_ids)
