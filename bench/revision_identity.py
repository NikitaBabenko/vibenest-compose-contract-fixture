"""Exact public-fixture identity; not a generic Git URL normalizer."""
def checks(app, uuid, repository, branch, sha):
    # ApplicationsController:1936–1939 stores the public GitHub URL as
    # owner/repository plus GithubApp source id0. Accept only these two exact
    # representations of the known fixture, never arbitrary host/path suffixes.
    return {
        'uuid':app.get('uuid')==uuid,
        'repository':app.get('git_repository') in (repository,'https://github.com/'+repository),
        'sourceType':app.get('source_type')=='App\\Models\\GithubApp',
        'sourceId':type(app.get('source_id')) is int and app['source_id']==0,
        'branch':app.get('git_branch')==branch,
        'commit':app.get('git_commit_sha')==sha,
        'buildPack':app.get('build_pack')=='dockercompose',
    }
