"""Virtual clock, time module patches, and the datetime swap."""

import datetime
import sys
import time
import types

import pytest

import hermetic
from hermetic import SandboxError


def test_wall_clock_frozen_at_start_time():
    with hermetic.sandbox(seed=1, now="2020-01-01T00:00:00+00:00"):
        assert time.time() == 1577836800.0
        assert time.time() == 1577836800.0  # frozen: repeated reads identical


def test_now_accepts_datetime_epoch_and_iso():
    when = datetime.datetime(2022, 3, 4, tzinfo=datetime.timezone.utc)
    for spec in (when, when.timestamp(), "2022-03-04T00:00:00+00:00"):
        with hermetic.sandbox(seed=1, now=spec):
            assert time.time() == when.timestamp()


def test_sleep_advances_wall_clock_without_blocking():
    with hermetic.sandbox(seed=1) as sb:
        real_before = sb.real.monotonic()
        start = time.time()
        time.sleep(3600)
        assert time.time() - start == pytest.approx(3600)
        assert sb.real.monotonic() - real_before < 5.0


def test_monotonic_ticks_and_orders():
    with hermetic.sandbox(seed=1, tick=0.001):
        a = time.monotonic()
        b = time.monotonic()
        assert b - a == pytest.approx(0.001)
        assert time.perf_counter() < time.perf_counter()


def test_time_ns_variants_are_ints():
    with hermetic.sandbox(seed=1):
        assert isinstance(time.time_ns(), int)
        assert isinstance(time.monotonic_ns(), int)
        assert isinstance(time.perf_counter_ns(), int)
        assert time.time_ns() == pytest.approx(time.time() * 1e9, rel=1e-9)


needs_tzset = pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="time.tzset is POSIX-only"
)


@needs_tzset
def test_localtime_family_uses_virtual_time():
    with hermetic.sandbox(seed=1, now="2020-06-15T12:00:00+00:00", env={"TZ": "UTC"}):
        time.tzset()
        assert time.gmtime().tm_year == 2020
        assert time.localtime().tm_mday == 15
        assert "2020" in time.ctime()
        assert time.strftime("%Y-%m-%d") == "2020-06-15"
        assert "2020" in time.asctime()
        # explicit argument stays a pure conversion
        assert time.gmtime(0).tm_year == 1970
    time.tzset()


def test_clock_control_advance_set_move_to():
    with hermetic.sandbox(seed=1, now="2020-01-01T00:00:00+00:00") as sb:
        sb.clock.advance(86400)
        assert time.strftime("%Y-%m-%d", time.gmtime(time.time())) == "2020-01-02"
        sb.clock.set("2030-05-05T00:00:00+00:00")
        assert datetime.datetime.now(datetime.timezone.utc).year == 2030
        sb.clock.move_to("2031-01-01T00:00:00+00:00")
        assert sb.clock.now().year == 2031


def test_spin_detector_raises_instead_of_hanging():
    with pytest.raises(SandboxError, match="spin"):
        with hermetic.sandbox(seed=1, spin_limit=500):
            for _ in range(1000):
                time.monotonic()


def test_sleep_resets_spin_counter():
    with hermetic.sandbox(seed=1, spin_limit=500):
        for _ in range(1000):
            time.monotonic()
            time.sleep(0.001)


def test_clock_off_leaves_time_real():
    before = time.time()
    with hermetic.sandbox(seed=1, clock="off") as sb:
        assert time.time() >= before
        with pytest.raises(SandboxError, match="clock"):
            sb.clock.advance(1)


def test_datetime_now_and_today_frozen():
    with hermetic.sandbox(seed=1, now="2020-01-01T00:00:00+00:00"):
        aware = datetime.datetime.now(datetime.timezone.utc)
        assert aware == datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        assert datetime.datetime.utcnow() == datetime.datetime(2020, 1, 1)
        # today() is local-time based; compare against the same conversion
        assert datetime.date.today() == datetime.date.fromtimestamp(1577836800.0)
        assert datetime.datetime.now().tzinfo is None  # naive, like the real one


def test_datetime_isinstance_compat_both_directions():
    real_instance = datetime.datetime(2000, 1, 1)
    with hermetic.sandbox(seed=1):
        fake_instance = datetime.datetime.now()
        assert isinstance(fake_instance, datetime.datetime)
        assert isinstance(real_instance, datetime.datetime)
    assert isinstance(fake_instance, datetime.datetime)


def test_datetime_arithmetic_stays_usable():
    with hermetic.sandbox(seed=1, now="2020-01-01T00:00:00+00:00"):
        base = datetime.datetime.now(datetime.timezone.utc)
        later = base + datetime.timedelta(days=3)
        assert later.day == 4
        assert isinstance(later, datetime.datetime)


@needs_tzset
def test_deep_datetime_scan_rewrites_from_imports():
    module = types.ModuleType("fake_user_module_for_hermetic_test")
    module.datetime = datetime.datetime
    module.date = datetime.date
    sys.modules[module.__name__] = module
    try:
        # noon UTC: today() converts via local time, which could otherwise land
        # a calendar day away from the UTC date on far-from-UTC machines.
        with hermetic.sandbox(seed=1, now="2020-06-15T12:00:00+00:00", env={"TZ": "UTC"}):
            time.tzset()
            assert module.datetime.now(datetime.timezone.utc).year == 2020
            assert module.date.today() == datetime.date(2020, 6, 15)
        assert module.datetime is datetime.datetime  # restored
    finally:
        time.tzset()
        del sys.modules[module.__name__]


def test_deep_datetime_false_skips_scan():
    module = types.ModuleType("fake_user_module_for_hermetic_test2")
    module.datetime = datetime.datetime
    sys.modules[module.__name__] = module
    try:
        with hermetic.sandbox(seed=1, deep_datetime=False):
            assert module.datetime.now().year >= 2026  # real class untouched
    finally:
        del sys.modules[module.__name__]


def test_strftime_asctime_reject_explicit_none_like_real():
    # noon mid-year: the same year in every local timezone
    with hermetic.sandbox(seed=1, now="2020-06-15T12:00:00+00:00"):
        with pytest.raises(TypeError):
            time.strftime("%Y", None)
        with pytest.raises(TypeError):
            time.asctime(None)
        # while omitted args still mean "virtual now"
        assert time.strftime("%Y") == "2020"


def test_user_datetime_subclass_keeps_normal_type_semantics():
    with hermetic.sandbox(seed=1):
        class Stamp(datetime.datetime):
            def tag(self):
                return "stamp"

        plain = datetime.datetime(2020, 1, 1)
        assert not isinstance(plain, Stamp)
        assert not issubclass(datetime.datetime, Stamp)
        inside = Stamp.now()
        assert type(inside) is Stamp and inside.tag() == "stamp"
    # the class permanently references the fakes; semantics must survive exit
    assert not isinstance(datetime.datetime(2020, 1, 1), Stamp)
    after = Stamp.now()
    assert type(after) is Stamp and after.tag() == "stamp"
    assert type(Stamp.today()) is Stamp


def test_time_module_restored_after_exit():
    originals = (time.time, time.monotonic, time.sleep, datetime.datetime)
    with hermetic.sandbox(seed=1):
        assert time.time is not originals[0]
    assert (time.time, time.monotonic, time.sleep, datetime.datetime) == originals
