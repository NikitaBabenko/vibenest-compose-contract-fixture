import json, pathlib, subprocess
p=pathlib.Path('evidence');p.mkdir(exist_ok=True)
r=subprocess.run(['docker','ps','-a','--format','{{json .}}'],text=True,capture_output=True)
(p/'containers.jsonl').write_text(r.stdout)
# Never export env files, tokens, raw inspect Env, repository copies or database dumps.
