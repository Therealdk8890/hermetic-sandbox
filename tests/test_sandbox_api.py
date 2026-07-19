"""Sandbox API surface: validation, nesting, decorator, handle, restoration."""

import asyncio
import time

import pytest

import hermetic
from hermetic import SandboxActiveError, SandboxError


@pytest.mark.parametrize(
    "kwargs",
    [
        {"clock": "banana"},
        {"rng": "banana"},
        {"fs": "banana"},
        {"fs": "fake"},
        {"network": "banana"},
        {"record": "a.json", "replay": "b.json"},
    ],
)
def test_invalid_parameters_raise_eagerly(kwargs):
    with pytest.raises(SandboxError):
        hermetic.sandbox(seed=1, **kwargs)


def test_nested_sandbox_raises():
    with hermetic.sandbox(seed=1):
        with pytest.raises(SandboxActiveError):
            with hermetic.sandbox(seed=2):
                pass


def test_sequential_reuse_of_one_instance():
    box = hermetic.sandbox(seed=7)
    with box:
        first = time.time()
    with box:
        second = time.time()
    assert first == second


def test_decorator_fresh_state_per_call():
    calls = []

    @hermetic.sandbox(seed=7)
    def sample():
        calls.append(time.time())
        time.sleep(10)

    sample()
    sample()
    assert calls[0] == calls[1]  # second call did not inherit the first's sleep


def test_async_decorator():
    @hermetic.sandbox(seed=7)
    async def sample():
        return time.time()

    first = asyncio.run(sample())
    second = asyncio.run(sample())
    assert first == second


def test_current_inside_and_outside():
    assert hermetic.current() is None
    with hermetic.sandbox(seed=1) as sb:
        assert hermetic.current() is sb
    assert hermetic.current() is None


def test_real_escape_hatches():
    with hermetic.sandbox(seed=1) as sb:
        assert sb.real.time() != time.time()
        assert sb.real.time() > 1.7e9
        assert len(sb.real.urandom(8)) == 8
        assert sb.real.uuid4() != sb.real.uuid4()


def test_handle_repr_and_mode():
    with hermetic.sandbox(seed=5) as sb:
        assert sb.mode == "deterministic"
        assert "seed=5" in repr(sb)


def test_everything_restored_when_body_raises():
    import datetime as datetime_module
    import os
    import socket

    originals = (
        time.time,
        datetime_module.datetime,
        os.urandom,
        socket.socket.connect,
        os.getcwd(),
    )
    with pytest.raises(RuntimeError, match="boom"):
        with hermetic.sandbox(seed=1, fs="isolate"):
            raise RuntimeError("boom")
    assert originals == (
        time.time,
        datetime_module.datetime,
        os.urandom,
        socket.socket.connect,
        os.getcwd(),
    )
    assert hermetic.current() is None


def test_exit_without_enter_raises():
    box = hermetic.sandbox(seed=1)
    with pytest.raises(SandboxError):
        box.__exit__(None, None, None)
