import copy
import unittest
from private_storage import (PROVIDER_COMMIT, PrestartRefusal, canonical_digest, normalize_bindings,
                             storage_decision, prestart_gate, literal_safe)

APP = 'fixtureapp1234'
NAMES = {'app-data': 'vnprivate-web', 'redis-data': 'vnprivate-redis'}


def model():
    return {'services': {service: {'volumes': [{'type': 'volume', 'source': APP+'_'+key, 'target': target}]}
                         for service, key, target in [('web', 'app-data', '/app/data'), ('redis', 'redis-data', '/data')]},
            'volumes': {APP+'_'+key: {'name': APP+'_'+key} for key in NAMES}}


def normalize(doc, **kw):
    args = dict(application=APP, provider_commit=PROVIDER_COMMIT, parser_version='5',
                pull_request_id=0, retained_names=NAMES, observed_digest=canonical_digest(doc))
    args.update(kw)
    return normalize_bindings(doc, **args)


class PrivateMappingTests(unittest.TestCase):
    def test_full_forward_key_and_unchanged_sources(self):
        original = model()
        effective, bindings = normalize(original)
        self.assertEqual(original, model())
        for b in bindings:
            self.assertEqual(effective['services'][b['service']], original['services'][b['service']])
            self.assertEqual(effective['volumes'][b['normalizedSourceKey']], {'name': b['physicalName'], 'external': True})

    def test_swapped_sources_at_same_target_fail(self):
        doc = model()
        a, b = [doc['services'][s]['volumes'][0] for s in ('web', 'redis')]
        a['source'], b['source'] = b['source'], a['source']
        with self.assertRaises(ValueError): normalize(doc)

    def test_mapping_drift_refused(self):
        mutations = [
            lambda d: d['volumes'].update({'app-data': {}}),
            lambda d: d['volumes'][APP+'_app-data'].update({'driver_opts': {'device': '/'}}),
            lambda d: d['volumes'][APP+'_app-data'].update({'name': 'other_app-data'}),
            lambda d: d['services']['web']['volumes'][0].update({'source': 'other_app-data'}),
            lambda d: d['services']['web']['volumes'][0].update({'read_only': True}),
            lambda d: d['services']['web']['volumes'][0].update({'volume': {'nocopy': True}}),
            lambda d: d['services']['web']['volumes'][0].update({'target': '/wrong'}),
            lambda d: d['services']['web']['volumes'].append(copy.deepcopy(d['services']['web']['volumes'][0])),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                doc = model(); mutate(doc)
                with self.assertRaises(ValueError): normalize(doc)

    def test_provider_context_refused(self):
        for args in [dict(parser_version='2'), dict(parser_version='6'), dict(pull_request_id=1),
                     dict(provider_commit='unknown'), dict(observed_digest='0'*64),
                     dict(retained_names={'app-data': 'same', 'redis-data': 'same'})]:
            with self.subTest(args=args), self.assertRaises(ValueError): normalize(model(), **args)


class PrivateStorageTests(unittest.TestCase):
    def setUp(self):
        self.row = {'Name': 'vnprivate-web', 'Driver': 'local', 'Scope': 'local', 'Options': None,
                    'CreatedAt': '2026-11-11T00:00:00Z', 'Labels': {'intent': 'a'*64}}
        self.args = dict(name='vnprivate-web', host='host1', expected_host='host1',
                         inventory=[], complete=True, intent_nonce='a'*64)

    def test_new_create_requires_absence_and_no_history(self):
        self.assertEqual(storage_decision('NewCreate', **self.args)['decision'], 'CreateOnceAfterDurableIntent')
        for args in [dict(inventory=[self.row]), dict(prior_observation=self.row), dict(complete=False), dict(host='host2')]:
            with self.subTest(args=args), self.assertRaises(ValueError): storage_decision('NewCreate', **(self.args | args))

    def test_retained_missing_never_becomes_create(self):
        for kind in ('RetainedInspect', 'ReconcileUnknown'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                storage_decision(kind, **self.args, prior_observation=self.row)
            got = storage_decision(kind, **(self.args | {'inventory': [self.row], 'prior_observation': self.row}))
            self.assertEqual(got['decision'], 'ObservedOnly')

    def test_same_name_recreation_and_bind_options_refused(self):
        for replacement in [self.row | {'CreatedAt': 'later'}, self.row | {'Options': {'type': 'none', 'device': '/'}}]:
            with self.subTest(row=replacement), self.assertRaises(ValueError):
                storage_decision('RetainedInspect', **(self.args | {'inventory': [replacement], 'prior_observation': self.row}))


class PrivatePrestartTests(unittest.TestCase):
    def setUp(self):
        _, self.bindings = normalize(model())
        self.images = {'web': 'sha256:'+'1'*64, 'redis': 'sha256:'+'2'*64}
        self.limits = {'web': (134217728, 250000000, 64), 'redis': (134217728, 250000000, 64)}
        self.rows = []
        for b in self.bindings:
            service = b['service']
            self.rows.append({'Image': self.images[service],
                'Config': {'User': 'node' if service == 'web' else '', 'Labels': {'com.docker.compose.service': service, 'com.docker.compose.project': APP}},
                'State': {'Status': 'created', 'Running': False, 'Restarting': False, 'StartedAt': '0001-01-01T00:00:00Z'},
                'HostConfig': {'Memory': 134217728, 'MemorySwap': 134217728, 'NanoCpus': 250000000, 'PidsLimit': 64, 'PortBindings': {},
                               'PublishAllPorts': False, 'Privileged': False, 'NetworkMode': APP+'_default', 'Binds': None, 'Devices': []},
                'Mounts': [{'Type': 'volume', 'Name': b['physicalName'], 'Destination': b['destination'], 'RW': True}]})

    def gate(self, rows):
        return prestart_gate(rows, application=APP, bindings=self.bindings, images=self.images, limits=self.limits)

    def test_created_nonroot_exact_resources(self):
        result = self.gate(self.rows)
        self.assertEqual(result['checkedServices'], ['redis', 'web'])
        self.assertEqual(result['mountRepresentations'], {'web': 'no-legacy-bind', 'redis': 'no-legacy-bind'})
        self.assertIs(result['productionStartAuthorized'], False)

    def test_exact_compose_named_bind_still_requires_matching_engine_mount(self):
        for row, binding in zip(self.rows, self.bindings, strict=True):
            row['HostConfig']['Binds'] = [f"{binding['physicalName']}:{binding['destination']}:rw"]
        result = self.gate(self.rows)
        self.assertEqual(result['mountRepresentations'], {'web': 'exact-named-bind', 'redis': 'exact-named-bind'})
        self.rows[0]['Mounts'][0]['Type'] = 'bind'
        with self.assertRaisesRegex(PrestartRefusal, '^prestart-engine-mount$'):
            self.gate(self.rows)

    def test_wrong_host_or_ambiguous_bind_is_refused(self):
        binding = self.bindings[0]
        correct = f"{binding['physicalName']}:{binding['destination']}:rw"
        for binds, extra_mounts, code in (
            (['/host:/app/data:rw'], None, 'prestart-absolute-host-bind'),
            ([r'C:\host:/app/data:rw'], None, 'prestart-absolute-host-bind'),
            (['../host:/app/data:rw'], None, 'prestart-unexpected-bind'),
            (['wrong-name:/app/data:rw'], None, 'prestart-unexpected-bind'),
            ([correct.replace(':rw', ':ro')], None, 'prestart-unexpected-bind'),
            ([correct+',nocopy'], None, 'prestart-unexpected-bind'),
            ([correct, correct], None, 'prestart-unexpected-bind'),
            (correct, None, 'prestart-unexpected-bind'),
            ([correct], [{'Type': 'volume'}], 'prestart-ambiguous-mount-spec'),
        ):
            with self.subTest(code=code, binds=binds):
                rows = copy.deepcopy(self.rows)
                rows[0]['HostConfig'].update(Binds=binds, Mounts=extra_mounts)
                with self.assertRaisesRegex(PrestartRefusal, f'^{code}$'):
                    self.gate(rows)

    def test_mount_image_limit_state_and_user_fail_closed(self):
        mutations = [
            lambda r: r[0]['State'].update({'Running': True}),
            lambda r: r[0]['State'].update({'Status': 'exited'}),
            lambda r: r[0]['State'].update({'StartedAt': '2026-11-11T00:00:00Z'}),
            lambda r: r[0].update({'Image': 'sha256:'+'0'*64}),
            lambda r: r[0]['Mounts'][0].update({'Name': 'other'}),
            lambda r: r[0]['Mounts'][0].update({'RW': False}),
            lambda r: r[0]['Mounts'][0].update({'Destination': '/other'}),
            lambda r: r[0]['Mounts'].append({'Type': 'bind', 'Destination': '/host'}),
            lambda r: r[0]['HostConfig'].update({'Memory': 0}),
            lambda r: r[0]['HostConfig'].update({'NanoCpus': 0}),
            lambda r: r[0]['HostConfig'].update({'PidsLimit': -1}),
            lambda r: r[0]['HostConfig'].update({'PortBindings': {'3000/tcp': [{'HostPort': '3000'}]}}),
            lambda r: r[0]['HostConfig'].update({'Privileged': True}),
            lambda r: r[0]['Config'].update({'User': 'root'}),
            lambda r: r.pop(),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                rows = copy.deepcopy(self.rows); mutate(rows)
                with self.assertRaises((ValueError, KeyError)): self.gate(rows)

    def test_literal_escape_preserves_keys_and_newlines(self):
        value = {'services': {'web': {'environment': {'LITERAL': 'a$b\n${CHANGED}\n"quote"', 'KEY$': '$$'}}}}
        escaped = literal_safe(value)
        self.assertEqual(escaped['services']['web']['environment'], {'LITERAL': 'a$$b\n$${CHANGED}\n"quote"', 'KEY$': '$$$$'})
        self.assertEqual(value['services']['web']['environment']['KEY$'], '$$')

    def test_memory_swap_unknown_unlimited_or_mismatch_refused(self):
        for value in (None, 0, -1, 268435456, '134217728', 134217728.0, False):
            with self.subTest(value=value):
                rows=copy.deepcopy(self.rows);rows[0]['HostConfig']['MemorySwap']=value
                with self.assertRaises(ValueError):self.gate(rows)
        rows=copy.deepcopy(self.rows);del rows[0]['HostConfig']['MemorySwap']
        with self.assertRaises(ValueError):self.gate(rows)


if __name__ == '__main__': unittest.main()
