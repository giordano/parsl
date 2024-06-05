import inspect
from concurrent.futures import Future
from typing import Any, Callable, Dict

import pytest

import parsl
from parsl.executors.base import ParslExecutor

N = 100
MAX_STACK = 50 

def local_config():
    return parsl.Config(executors=[ImmediateExecutor()])

class ImmediateExecutor(ParslExecutor):
    def start(self):
        pass

    def shutdown(self):
        pass

    def submit(self, func: Callable, resource_specification: Dict[str, Any], *args: Any, **kwargs: Any) -> Future:
        stack_depth = len(inspect.stack())
        assert stack_depth < MAX_STACK, "tasks should not be launched deep in the Python stack"
        fut = Future()
        res = func(*args, **kwargs)
        fut.set_result(res)
        return fut

@parsl.python_app
def chain(upstream):
    stack_depth = len(inspect.stack())
    assert stack_depth < MAX_STACK, "chained dependencies should not be launched deep in the Python stack"


@pytest.mark.local
def test_deep_dependency_stack_depth():

    fut = Future()
    here = fut

    for _ in range(N):
        here = chain(here)

    fut.set_result(None)
    here.result()
