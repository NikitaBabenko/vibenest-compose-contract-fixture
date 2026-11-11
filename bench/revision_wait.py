"""Bounded read-only reconciliation; never dispatches or retries a mutation."""
import time

def wait_for_removal(read_runtime, *, timeout=120, interval=1,
                     now=time.monotonic, sleep=time.sleep, observe=lambda elapsed, rows: None,
                     read_with_deadline=False):
    if not 0 < timeout <= 120 or not 0 < interval <= timeout:
        raise ValueError('Invalid bounded removal wait')
    started=now();deadline=started+timeout
    while True:
        rows=read_runtime(deadline) if read_with_deadline else read_runtime()
        # Transport/inspection errors propagate; unknown is not empty.
        elapsed=now()-started
        if not isinstance(rows,list):
            raise RuntimeError('Runtime observation unavailable; no successor start')
        observe(elapsed,rows)
        if rows==[] and now()<=deadline:
            return rows
        remaining=deadline-now()
        if remaining<=0:
            raise TimeoutError('Container removal unconfirmed; no successor start')
        sleep(min(interval,remaining))
