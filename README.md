# hermetic

**One context manager that makes a block of code deterministic** — frozen time,
seeded randomness (`uuid4` and `secrets` included), blocked network, and an
optional isolated filesystem, all keyed to a single seed you can replay.

Instead of stacking `freezegun` + `pyfakefs` + `responses` + a hand-rolled
`random.seed()` and hoping they compose, you write:

```python
import hermetic

with hermetic.sandbox(seed=42) as sb:
    ...  # same time, same uuids, same tokens, same random stream — every run
```

And the part nobody else has built: **record/replay**. Capture the actual
nondeterminism from a failing CI run as a journal artifact, download it, and
feed the exact same values back into the test on your laptop:

```bash
# CI
pytest --hermetic-all --hermetic-record=journals/     # upload journals/ on failure

# your machine, after downloading the artifact
pytest 'tests/test_checkout.py::test_flaky' --hermetic-replay=journals/tests-test_checkout...json.gz
```

A flaky test stops being folklore ("it fails sometimes on CI??") and becomes a
file you can re-run.

Zero dependencies. Python 3.10+. MIT. **Not a security boundary** — code inside
the sandbox can trivially escape via C extensions or subprocesses; this is a
determinism tool for tests, nothing more.

## Install

```bash
pip install hermetic-sandbox
```

(The distribution is named `hermetic-sandbox` on PyPI; the import is plain
`import hermetic`.)

The pytest plugin activates automatically (it does nothing until you use a
marker, fixture, or `--hermetic-*` option).

## What it controls

| Subsystem | Default | What happens | Off switch |
|---|---|---|---|
| Wall clock | `clock="virtual"` | `time.time`, `datetime.now`, `localtime`… frozen at `now=` (default 2020-01-01 UTC). `time.sleep(n)` advances the clock by `n` and never blocks. Naive `datetime.now()`/`date.today()` convert the frozen instant to the machine's **local** timezone, exactly like the real clock — use `datetime.now(timezone.utc)` or `sb.clock.now()` for TZ-independent values. | `clock="off"` |
| Monotonic clocks | (same) | `monotonic`/`perf_counter` advance by `tick=` (default 1 µs) per reading, so elapsed-time math and deadline polls make progress. | `tick=0` freezes them too |
| Randomness | `rng="all"` | Global `random` seeded; `os.urandom` and `random._urandom` become PRNG-backed — which makes `uuid.uuid4()`, `secrets.*`, and `random.SystemRandom` deterministic. | `rng="seed"` (only `random`), `rng="off"` |
| Network | `network="block"` | `connect`/`connect_ex`/`sendto` **and DNS resolution** raise `NetworkBlockedError` (a `ConnectionRefusedError` subclass, so existing error handling degrades gracefully). Loopback and unix sockets stay allowed (`allow_loopback` / `allow_unix`). | `network="off"`, or an allowlist: `network=["api.example.com:443"]` — with the default `rng="all"` an allowlist emits a `UserWarning` (real TLS fed deterministic entropy); pair it with `rng="seed"` |
| Filesystem | `fs="off"` | Opt in with `fs="isolate"`: fresh tempdir for cwd/`HOME`/`TMPDIR`, deleted on exit. (`chdir=False` redirects HOME/TMPDIR without moving cwd.) | default |
| Environment | restore-on-exit | `env={...}` overrides (`None` deletes), `scrub_env=True` drops everything but a safe allowlist. | — |

Every subsystem is independent: `sandbox(clock="off", rng="off")` is just a
network blocker.

### The handle

```python
with hermetic.sandbox(seed=42, now="2021-06-01T00:00:00+00:00") as sb:
    sb.seed                      # 42 — always printed/printable for repro
    sb.clock.advance(3600)       # move virtual time
    sb.clock.set("2022-01-01")   # or jump (move_to is an alias)
    sb.clock.now()               # aware UTC datetime, without ticking
    sb.real.time()               # escape hatches to the un-patched world:
    sb.real.urandom(16)          # real entropy for the one call that needs it
    sb.allow_network("localhost:5432")  # extend the allowlist at runtime
hermetic.current()               # the active handle from anywhere, or None
```

`sandbox(...)` is also a decorator (sync and async functions), creating fresh
state per call.

## pytest

```python
import pytest

@pytest.mark.hermetic                       # sandbox this test
def test_order_ids_are_stable(): ...

@pytest.mark.hermetic(network="off", seed=7)  # marker kwargs = sandbox kwargs
def test_with_real_network(): ...

def test_time_travel(hermetic_sandbox):     # fixture gives you the handle
    hermetic_sandbox.clock.advance(86400)
```

The **marker configures, the fixture accesses** — using both on one test is
fine. `--hermetic-all` sandboxes every test (opt out per-test with
`@pytest.mark.hermetic(off=True)`).

Seeds: each test's seed is derived from its node id XOR a session **base seed**
(printed in the header, propagated to xdist workers), so re-running any failing
test with `--hermetic-seed=<base>` reproduces it regardless of test order or
parallelism. Failing sandboxed tests print a copy-pasteable repro command.

### The CI record/replay loop

1. CI runs `pytest --hermetic-all --hermetic-record=journals/`.
2. Every sandboxed test records real values as it runs. Journals for **failing
   attempts are kept** (a later passing retry from a rerun plugin never deletes
   them); passing tests leave nothing. `journals/index.json` maps files to tests.
3. Upload `journals/` as a CI artifact when the job fails.
4. Locally: `pytest --hermetic-replay=path/to/journal.json.gz`. The plugin
   selects the recorded test automatically and feeds back the recorded clock
   readings, urandom draws, and `random` state. The journal's recorded
   configuration wins over local options, and replay warns loudly about
   anything that makes it less than faithful (different Python/TZ/locale/
   PYTHONHASHSEED, multi-threaded recording, event-cap overflow).

Set `PYTHONHASHSEED` explicitly in CI — dict/set-iteration-order flakes can't
be replayed without it, and the repro hint includes it when set.

### What's in a journal (read before uploading anywhere public)

Clock readings, **verbatim urandom draws** (any token/key the test derived from
them is recoverable), the `random` state, environment variable **names only** —
except the values of `TZ` and `PYTHONHASHSEED` (and the locale string), which
the fingerprint stores for replay-fidelity warnings — plus hostname, platform,
and git SHA. Treat journals like logs:
private artifact storage, short retention (7–14 days is plenty — a journal is
only useful until the flake is fixed).

## Honest limitations

- **Threads**: patches are process-global; the virtual clock affects all
  threads, but `threading.Event.wait`/`Condition.wait`/lock timeouts block in C
  against the *real* clock and can't be virtualized. A thread that calls the
  patched (non-blocking) `sleep` in a loop will busy-spin. Multi-threaded
  recording is detected and stamped in the journal; replay warns.
- **asyncio**: virtual time is not supported in v0.1. `loop.time()` does follow
  the patched `time.monotonic`, but the event loop blocks in
  `selector.select()` in C — `await asyncio.sleep(n)` under a frozen clock
  hangs. Use `clock="off"` for async tests that await sleeps/timeouts.
  (The spin detector catches synchronous poll loops, raising a diagnostic
  error instead of hanging CI.)
- **C-level entropy**: OpenSSL's CSPRNG (TLS), C callers of `_PyOS_URandom`,
  `os.getrandom`, and direct `/dev/urandom` reads bypass Python-level patches.
- **datetime in C extensions**: the datetime swap covers Python code (including
  `from datetime import datetime` references, via the `deep_datetime` scan);
  C extensions using the `PyDateTimeAPI` capsule (numpy, some DB drivers) see
  the real type.
- **Network replay**: journals do not capture traffic (that's VCR's job); a
  recording made with a network allowlist replays with a warning that those
  calls are uncaptured.
- **Subprocesses** inherit nothing: patches live in this interpreter.

## Recipes

**numpy** (deliberately not built in):

```python
with hermetic.sandbox(seed=42) as sb:
    rng = np.random.default_rng(sb.seed)   # derive from the sandbox seed
```

**pyfakefs**: compose, don't stack — `hermetic.sandbox(fs="off")` plus pyfakefs's
own fixture works fine; hermetic's `fs="isolate"` is a real tempdir, not a fake.

**Migrating from freezegun**: `sandbox(now=...)` ≈ `freeze_time(...)`;
`sb.clock.move_to(...)` matches; `tick=` exists but applies to
monotonic/perf_counter (wall time only moves via `sleep`/`advance`). One
difference: freezegun makes naive `datetime.now()` equal the frozen input
verbatim, while hermetic keeps real-clock semantics — the frozen instant
converted to local time. Freeze with an explicit offset or compare aware
datetimes to stay TZ-independent.

## API summary

```python
hermetic.sandbox(
    seed=None,                 # int | None (None → generated, exposed on sb.seed)
    now="2020-01-01T00:00:00+00:00",  # ISO str | datetime | epoch seconds
    tick=1e-6,                 # monotonic/perf auto-advance per reading; 0 = frozen
    clock="virtual",           # "virtual" | "off"
    rng="all",                 # "all" | "seed" | "off"
    network="block",           # "block" | "off" | ["host", "host:port", ...]
    allow_loopback=True, allow_unix=True,
    fs="off",                  # "off" | "isolate"
    chdir=True,                # move cwd when isolating
    env=None, scrub_env=False, # overrides / allowlist scrub
    record=None, replay=None,  # journal paths (.gz → gzip); mutually exclusive
    strict_replay=True,        # divergence raises ReplayExhausted/ReplayMismatch
    deep_datetime=True,        # rewrite `from datetime import datetime` refs
    spin_limit=1_000_000,      # frozen-clock poll-loop detector; 0 disables
)
```

Errors: `SandboxError` ⊃ `SandboxActiveError` (no nesting),
`NetworkBlockedError` (also a `ConnectionRefusedError`), `ReplayError` ⊃
`ReplayExhausted`, `ReplayMismatch`.
