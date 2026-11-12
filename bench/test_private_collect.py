import copy
import hashlib
import json
import unittest
from private_collect import verify_missing_refusal


class MissingRefusalTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(project='project', application='app', attempt='attempt', deployment='deployment',
                          generation=1, sourceSha='a'*40, helperDigest='b'*64, settingsDigest='c'*64)
        self.names = ['vnprivate1-redis', 'baseline']
        self.name = 'vnprivate11-web'
        self.receipt = dict(schema=1, scope=copy.deepcopy(self.scope), stage='retained-volume-inspection',
                            code='assigned-volume-missing', createIssued=False,
                            volumeNameDigest=hashlib.sha256(self.name.encode()).hexdigest(),
                            inventoryDigest=hashlib.sha256(json.dumps(sorted(self.names), separators=(',', ':')).encode()).hexdigest())

    def verify(self, receipt, **kwargs):
        args = dict(scope=self.scope, expected_name=self.name, inventory=self.names, complete=True)
        return verify_missing_refusal(receipt, **(args | kwargs))

    def test_exact_cause_and_independent_inventory(self):
        self.assertEqual(self.verify(self.receipt), self.receipt)
        self.assertNotIn(self.name, json.dumps(self.verify(self.receipt)))
        self.assertEqual(self.verify(self.receipt, inventory=list(reversed(self.names))), self.receipt)

    def test_generic_or_wrong_stage_failure_cannot_pass(self):
        for receipt in [None, {}, {'status':'failed'}, self.receipt | {'stage':'source-verification'},
                        self.receipt | {'code':'source-mismatch'}, self.receipt | {'stage':'volume-list'},
                        self.receipt | {'createIssued':True}, self.receipt | {'createIssued':None},
                        self.receipt | {'createIssued':0}, self.receipt | {'schema':True},
                        self.receipt | {'volumeNameDigest':'d'*64}, self.receipt | {'inventoryDigest':'d'*64},
                        self.receipt | {'unexpected':'name'}]:
            with self.subTest(receipt=receipt), self.assertRaises(ValueError): self.verify(receipt)
        for key in self.receipt:
            receipt=copy.deepcopy(self.receipt); del receipt[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): self.verify(receipt)
        for key in self.scope:
            receipt=copy.deepcopy(self.receipt); receipt['scope'][key] = 2 if key == 'generation' else 'other'
            with self.subTest(scope=key), self.assertRaises(ValueError): self.verify(receipt)

    def test_unknown_or_conflicting_independent_inventory_refused(self):
        for kw in [dict(complete=False), dict(complete=None), dict(inventory=None),
                   dict(inventory=self.names+[self.name]), dict(inventory=self.names+self.names),
                   dict(inventory=['']), dict(inventory=['unexpected']), dict(expected_name='vnprivate12-web')]:
            with self.subTest(kw=kw), self.assertRaises(ValueError): self.verify(self.receipt, **kw)


if __name__ == '__main__': unittest.main()
