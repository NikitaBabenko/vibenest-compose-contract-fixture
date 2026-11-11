import json
import subprocess
import unittest
from revision_inventory import read_containers
from revision_wait import wait_for_removal

A, B = 'a' * 64, 'b' * 64


def row(identity):
    return {'Id': identity, 'Config': {'Labels': {'com.docker.compose.project': 'app'}}}


def missing(identity=A, stderr=None):
    return subprocess.CalledProcessError(1, ['docker', 'inspect'],
        output=json.dumps([row(B)]), stderr=stderr or 'error: no such object: ' + identity + '\n')


class InventoryTests(unittest.TestCase):
    def reader(self, replies, clock=lambda: 0, deadline=120):
        calls = []
        def execute(args, **kwargs):
            calls.append((args, kwargs))
            answer = replies.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        return lambda: read_containers('app', execute=execute, now=clock, deadline=deadline), calls

    def test_removed_between_list_and_inspect_requires_new_successful_snapshot(self):
        read, calls = self.reader([A + '\n' + B, missing(), B, json.dumps([row(B)]), B])
        self.assertEqual(read(), [row(B)])
        self.assertEqual(len(calls), 5)
        self.assertIn('label=com.docker.compose.project=app', calls[0][0])
        self.assertIn('--no-trunc', calls[0][0])

    def test_removed_last_container_needs_successful_empty_enumeration(self):
        read, calls = self.reader([A, missing(), ''])
        self.assertEqual(read(), [])
        self.assertEqual(len(calls), 3)

    def test_unknown_transport_permission_and_mixed_errors_propagate(self):
        for error in (OSError('daemon unavailable'), subprocess.TimeoutExpired('docker', 10),
                      missing(stderr='permission denied'),
                      missing(stderr='error: no such object: ' + A + '\nconnection reset'),
                      missing(B)):
            with self.subTest(error=type(error).__name__):
                read, calls = self.reader([A, error, ''])
                with self.assertRaises(type(error)):
                    read()
                self.assertEqual(len(calls), 2)

    def test_reenumeration_failure_does_not_mean_empty(self):
        read, _ = self.reader([A, missing(), OSError('daemon unavailable')])
        with self.assertRaises(OSError):
            read()

    def test_changed_successful_snapshot_is_read_again(self):
        read, _ = self.reader([A, json.dumps([row(A)]), B, B, json.dumps([row(B)]), B])
        self.assertEqual(read(), [row(B)])

    def test_repeated_deletion_races_fail_closed_after_three_attempts(self):
        read, calls = self.reader([A, missing()] * 3 + [''])
        with self.assertRaises(RuntimeError):
            read()
        self.assertEqual(len(calls), 6)

    def test_invalid_identity_shape_labels_or_partial_inspection_refuse(self):
        for result in ('[]', json.dumps([row(B)]), json.dumps([row(A), row(A)]),
                       json.dumps([{'Id': A, 'Config': {'Labels': {'com.docker.compose.project': 'other'}}}]),
                       '{}', 'not json'):
            with self.subTest(result=result):
                read, _ = self.reader([A, result])
                with self.assertRaises((RuntimeError, ValueError)):
                    read()
        for ids in ('shortid', A + '\n' + A, ('c' * 64 + '\n') * 33):
            read, _ = self.reader([ids])
            with self.assertRaises(RuntimeError):
                read()

    def test_remaining_outer_deadline_limits_every_command(self):
        ticks = iter([117, 118, 119])
        read, calls = self.reader([A, json.dumps([row(A)]), A], clock=lambda: next(ticks))
        self.assertEqual(read(), [row(A)])
        self.assertEqual([call[1]['timeout'] for call in calls], [3, 2, 1])
        ticks = iter([119, 120])
        read, calls = self.reader([A, ''], clock=lambda: next(ticks))
        with self.assertRaises(TimeoutError):
            read()
        self.assertEqual(len(calls), 1)

    def test_wait_passes_one_absolute_deadline_across_observations(self):
        clock = [50]
        deadlines = []
        def read(deadline):
            deadlines.append(deadline)
            return [row(A)] if clock[0] < 52 else []
        def sleep(seconds):
            clock[0] += seconds
        self.assertEqual(wait_for_removal(read, now=lambda: clock[0], sleep=sleep,
                         read_with_deadline=True), [])
        self.assertEqual(deadlines, [170, 170, 170])


if __name__ == '__main__':
    unittest.main()
