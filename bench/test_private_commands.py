import unittest
from private_commands import bootstrap_command, START_COMMAND


class PrivateCommandTests(unittest.TestCase):
    def setUp(self):
        self.broker={'origin':'https://172.18.0.1:45678','caURL':'http://172.18.0.1:45679/ca.pem',
                     'caDigest':'a'*64,'helperDigest':'b'*64,'helperSize':9000000}

    def test_secretless_bounded_command_and_explicit_rewrite_marker(self):
        command=bootstrap_command('NikitaBabenko/vibenest-compose-contract-fixture','c'*40,self.broker)
        self.assertLessEqual(len(command),1000)
        self.assertIn('--project-directory .',command)
        self.assertNotIn(' build ',command)
        self.assertNotIn('docker compose',command)
        self.assertNotIn('Authorization',command)
        self.assertIn('--project-directory .',START_COMMAND)

    def test_bad_url_digest_and_repository_refused(self):
        for broker in [self.broker|{'origin':'http://172.18.0.1:42'}, self.broker|{'caDigest':'latest'},
                       self.broker|{'caURL':'http://172.18.0.1:42/ca.pem?token=secret'}, self.broker|{'helperSize':2**30}]:
            with self.subTest(broker=broker),self.assertRaises(ValueError): bootstrap_command('o/r','c'*40,broker)
        with self.assertRaises(ValueError): bootstrap_command("bad';echo x",'c'*40,self.broker)


if __name__=='__main__':unittest.main()
