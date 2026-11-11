import unittest
from revision_wait import wait_for_removal

class Clock:
    def __init__(self):self.elapsed=0
    def now(self):return self.elapsed
    def sleep(self,seconds):self.elapsed+=seconds

class RemovalWaitTests(unittest.TestCase):
    def run_wait(self,clock,read,**kwargs):
        return wait_for_removal(read,now=clock.now,sleep=clock.sleep,**kwargs)

    def test_observed_30_second_grace_then_serial_second_service(self):
        clock=Clock();seen=[]
        def read():
            if clock.elapsed<30.1:return ['web','redis']
            if clock.elapsed<31.1:return ['redis']
            return []
        self.assertEqual(self.run_wait(clock,read,observe=lambda t,r:seen.append((t,r))),[])
        self.assertEqual(clock.elapsed,32)
        self.assertIn((31,['redis']),seen)

    def test_both_services_may_consume_full_serial_grace(self):
        clock=Clock()
        self.assertEqual(self.run_wait(clock,lambda: ['redis'] if clock.elapsed<60.2 else []),[])
        self.assertEqual(clock.elapsed,61)

    def test_never_removed_is_bounded_and_rejected(self):
        clock=Clock()
        with self.assertRaises(TimeoutError):self.run_wait(clock,lambda:['running'])
        self.assertEqual(clock.elapsed,120)

    def test_stopped_container_is_not_removal(self):
        clock=Clock()
        with self.assertRaises(TimeoutError):self.run_wait(clock,lambda:[{'state':'exited'}])

    def test_unknown_or_failed_inspection_never_passes(self):
        for result in [None,{},False]:
            with self.assertRaises(RuntimeError):self.run_wait(Clock(),lambda:result)
        def failed():raise OSError('inspection failed')
        with self.assertRaises(OSError):self.run_wait(Clock(),failed)

    def test_empty_observed_after_deadline_is_not_accepted(self):
        clock=Clock()
        def read():clock.elapsed=121;return []
        with self.assertRaises(TimeoutError):self.run_wait(clock,read)

    def test_immediate_empty_and_final_boundary_observation(self):
        clock=Clock();self.assertEqual(self.run_wait(clock,lambda:[]),[])
        self.assertEqual(clock.elapsed,0)
        self.assertEqual(self.run_wait(clock,lambda:['web'] if clock.elapsed<120 else []),[])

    def test_unbounded_wait_configuration_rejected(self):
        for timeout in [0,-1,121,float('inf')]:
            with self.assertRaises(ValueError):self.run_wait(Clock(),lambda:[],timeout=timeout)
