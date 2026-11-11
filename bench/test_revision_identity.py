import unittest
from revision_identity import checks

class RevisionIdentityTests(unittest.TestCase):
    def identity(self):
        return {'uuid':'fixture-app','git_repository':'owner/repo','source_type':'App\\Models\\GithubApp',
                'source_id':0,'git_branch':'fixture','git_commit_sha':'1'*40,'build_pack':'dockercompose'}

    def verify(self,value):
        return all(checks(value,'fixture-app','owner/repo','fixture','1'*40).values())

    def test_pinned_provider_public_github_storage_shape(self):
        self.assertTrue(self.verify(self.identity()))
        original=self.identity();original['git_repository']='https://github.com/owner/repo'
        self.assertTrue(self.verify(original))

    def test_any_changed_or_missing_anchor_rejected(self):
        for key in self.identity():
            changed=self.identity();changed[key]='changed'
            self.assertFalse(self.verify(changed),key)
            del changed[key]
            self.assertFalse(self.verify(changed),key)

    def test_untrusted_hosts_and_suffix_matches_rejected(self):
        for repository in ['https://evil.example/owner/repo','other-owner/repo',
                           'owner/repo-extra','https://github.com.evil/owner/repo','owner/repo.git']:
            changed=self.identity();changed['git_repository']=repository
            self.assertFalse(self.verify(changed))
