"""Randomness determinization: random, os.urandom, uuid4, secrets."""

import os
import random
import secrets
import uuid

import hermetic


def _draws():
    return (
        random.random(),
        os.urandom(8).hex(),
        uuid.uuid4().hex,
        secrets.token_hex(8),
        random.SystemRandom().random(),
    )


def test_same_seed_same_streams():
    with hermetic.sandbox(seed=42):
        first = _draws()
    with hermetic.sandbox(seed=42):
        second = _draws()
    assert first == second


def test_different_seed_different_streams():
    with hermetic.sandbox(seed=1):
        first = _draws()
    with hermetic.sandbox(seed=2):
        second = _draws()
    assert first != second


def test_uuid4_is_valid_version_4():
    with hermetic.sandbox(seed=42):
        value = uuid.uuid4()
    assert value.version == 4
    assert value.variant == uuid.RFC_4122


def test_rng_seed_mode_leaves_urandom_real():
    with hermetic.sandbox(seed=42, rng="seed"):
        a = uuid.uuid4()
    with hermetic.sandbox(seed=42, rng="seed"):
        b = uuid.uuid4()
    assert a != b  # urandom not determinized
    with hermetic.sandbox(seed=42, rng="seed"):
        r1 = random.random()
    with hermetic.sandbox(seed=42, rng="seed"):
        r2 = random.random()
    assert r1 == r2  # but the global random instance is


def test_rng_off_leaves_global_random_alone():
    random.seed(999)
    expected = random.Random(999).random()
    with hermetic.sandbox(seed=42, rng="off"):
        assert random.random() == expected


def test_global_random_state_restored_after_exit():
    random.seed(1234)
    reference = random.Random(1234)
    assert random.random() == reference.random()
    with hermetic.sandbox(seed=42):
        random.random()
        random.random()
    # the sandbox's seeding and draws must not have advanced the outer stream
    assert random.random() == reference.random()


def test_urandom_restored_after_exit():
    with hermetic.sandbox(seed=42):
        inside = os.urandom
    assert os.urandom is not inside
    assert len(os.urandom(4)) == 4


def test_seed_none_generates_and_exposes_seed():
    with hermetic.sandbox() as sb:
        assert isinstance(sb.seed, int)
        first = random.random()
    with hermetic.sandbox(seed=sb.seed):
        assert random.random() == first  # printable seed reproduces the run
