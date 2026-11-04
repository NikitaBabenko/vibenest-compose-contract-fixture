import json, pathlib, subprocess
p=pathlib.Path('evidence');p.mkdir(exist_ok=True)
r=subprocess.run(['docker','ps','-a','--format','{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}'],text=True,capture_output=True)
(p/'containers.txt').write_text(r.stdout)
# Never export env files, tokens, raw inspect Env, repository copies or database dumps.
