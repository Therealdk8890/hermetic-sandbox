"""Filesystem isolation and environment handling."""

import os
import pathlib
import tempfile

import hermetic


def test_fs_off_by_default():
    cwd = os.getcwd()
    with hermetic.sandbox(seed=1) as sb:
        assert os.getcwd() == cwd
        assert sb.fs is None


def test_fs_isolate_redirects_cwd_home_tmp():
    outer_cwd = os.getcwd()
    outer_home = os.environ.get("HOME")
    with hermetic.sandbox(seed=1, fs="isolate") as sb:
        assert pathlib.Path.cwd() == sb.fs.cwd
        assert os.environ["HOME"] == str(sb.fs.home)
        assert os.environ["TMPDIR"] == str(sb.fs.tmp)
        assert tempfile.gettempdir() == str(sb.fs.tmp)
        with tempfile.NamedTemporaryFile() as handle:
            assert handle.name.startswith(str(sb.fs.tmp))
        (sb.fs.cwd / "scratch.txt").write_text("data")
    assert os.getcwd() == outer_cwd
    assert os.environ.get("HOME") == outer_home
    assert not sb.fs.root.exists()  # tree deleted on exit


def test_fs_isolate_restores_tempfile_tempdir_cache():
    original = tempfile.tempdir
    tempfile.tempdir = None  # the untouched-process default
    try:
        with hermetic.sandbox(seed=1, fs="isolate"):
            pass
        assert tempfile.tempdir is None  # not polluted by mkdtemp's caching
    finally:
        tempfile.tempdir = original


def test_fs_isolate_without_chdir():
    cwd = os.getcwd()
    with hermetic.sandbox(seed=1, fs="isolate", chdir=False) as sb:
        assert os.getcwd() == cwd
        assert os.environ["HOME"] == str(sb.fs.home)


def test_env_overrides_applied_and_restored():
    os.environ["HERMETIC_TEST_KEEP"] = "outer"
    try:
        with hermetic.sandbox(
            seed=1,
            env={"HERMETIC_TEST_NEW": "inner", "HERMETIC_TEST_KEEP": None},
        ):
            assert os.environ["HERMETIC_TEST_NEW"] == "inner"
            assert "HERMETIC_TEST_KEEP" not in os.environ
        assert os.environ["HERMETIC_TEST_KEEP"] == "outer"
        assert "HERMETIC_TEST_NEW" not in os.environ
    finally:
        os.environ.pop("HERMETIC_TEST_KEEP", None)


def test_scrub_env_keeps_essentials_drops_rest():
    os.environ["HERMETIC_SUPER_SECRET"] = "hunter2"
    try:
        with hermetic.sandbox(seed=1, scrub_env=True):
            assert "HERMETIC_SUPER_SECRET" not in os.environ
            os.environ["TOTALLY_CUSTOM_VAR"] = "x"
        with hermetic.sandbox(seed=1, scrub_env=True, env={"HERMETIC_SUPER_SECRET": None}):
            assert "HERMETIC_SUPER_SECRET" not in os.environ
            assert "PATH" in os.environ
        assert os.environ["HERMETIC_SUPER_SECRET"] == "hunter2"
    finally:
        os.environ.pop("HERMETIC_SUPER_SECRET", None)


def test_scrub_env_drops_unknown_variables():
    os.environ["SOME_RANDOM_TOKEN_XYZ"] = "leaky"
    try:
        with hermetic.sandbox(seed=1, scrub_env=True):
            assert "SOME_RANDOM_TOKEN_XYZ" not in os.environ
        assert os.environ["SOME_RANDOM_TOKEN_XYZ"] == "leaky"
    finally:
        os.environ.pop("SOME_RANDOM_TOKEN_XYZ", None)
