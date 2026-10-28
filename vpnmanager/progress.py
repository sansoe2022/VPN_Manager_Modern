"""Visible operation stages and elapsed-time heartbeats for long backup work."""
from contextlib import contextmanager
from functools import wraps
import threading
import time


@contextmanager
def stage(label):
    print(label + '...', flush=True)
    stopped = threading.Event()
    start = time.monotonic()
    def pulse():
        while not stopped.wait(2):
            print(f'  Working... {int(time.monotonic() - start)}s elapsed', flush=True)
    thread = threading.Thread(target=pulse, daemon=True)
    thread.start()
    try:
        yield
    except BaseException:
        stopped.set(); thread.join()
        print('  Failed. See the error below.', flush=True)
        raise
    else:
        stopped.set(); thread.join()
        print(f'  Done ({time.monotonic() - start:.1f}s)', flush=True)


def operation(label):
    def decorate(function):
        @wraps(function)
        def run(*args, **kwargs):
            with stage(label):
                return function(*args, **kwargs)
        return run
    return decorate


def transfer(received, total):
    amount = received / 1024 ** 2
    if total:
        print(f'  Download: {amount:.1f}/{total / 1024 ** 2:.1f} MiB ({received * 100 // total}%)', flush=True)
    else:
        print(f'  Download: {amount:.1f} MiB', flush=True)
