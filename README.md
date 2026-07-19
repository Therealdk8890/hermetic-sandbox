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
PYTHONHASHSEED=0 pytest --hermetic-all \
  --hermetic-record=.hermetic-journals/

# your machine, after downloading the artifact
hermetic replay .hermetic-journals/
```

A flaky test stops being folklore ("it fails sometimes on CI??") and becomes a
file you can re-run.

Zero dependencies in the core. Python 3.10+. MIT. Client-side journal encryption
is an optional extra. **Not a security boundary** — code inside the sandbox can
trivially escape via C extensions or subprocesses; this is a determinism tool
for tests, nothing more.

## Install

```bash
pip install hermetic-sandbox

# Needed only to encrypt CI journals before upload:
pip install 'hermetic-sandbox[secure]'
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

1. CI runs
   `PYTHONHASHSEED=0 pytest --hermetic-all --hermetic-record=.hermetic-journals/`.
2. One sandbox spans fixture setup, the test call, and fixture teardown.
   Journals for **failing attempts are kept**; passing tests leave nothing.
   Files have opaque names and mode `0600` on POSIX. On Windows, raw journals,
   indexes, sealed journals, and decrypted replay paths use a protected DACL
   with exactly one full-control entry for the current user, and fail closed if
   that postcondition cannot be verified.
3. Before any upload, run
   `hermetic journal inspect .hermetic-journals/<journal>.json.gz`. The command
   fails closed for malformed data, credential-shaped metadata, unsafe
   permissions, or replay-sensitive plaintext.
4. Sensitive journals must be encrypted locally:

   ```bash
   # HERMETIC_JOURNAL_KEY is a URL-safe-base64 encoding of exactly 32 random bytes.
   hermetic journal seal .hermetic-journals/ \
     --output .hermetic-sealed-journals/
   ```

   Upload only `.hermetic-sealed-journals/`, with short retention. Keep the key
   in a CI secret and your team password manager; it is removed from the pytest
   subprocess environment during replay.
5. After download, one command selects the recorded test, restores its
   `PYTHONHASHSEED`, decrypts into a private temporary file when needed, and
   removes that file afterward:

   ```bash
   gh run download RUN_ID --name hermetic-journals \
     --dir .hermetic-sealed-journals/
   hermetic replay .hermetic-sealed-journals/
   ```

Strict replay verifies the global order of captured events, rejects missing or
extra events, compares the final global `random` state, and refuses event-cap,
cross-thread, Python, hash-seed, source, test-file, Hermetic, and pytest
mismatches. Platform and locale differences remain explicit warnings because
captured Python-level inputs can still replay across them. Use
`strict_replay=False` only for exploratory best-effort replay.

Set `PYTHONHASHSEED` explicitly in CI — dict/set-iteration-order flakes cannot
be replayed without it. The `hermetic replay` command restores the recorded
value before launching pytest.

### Journal security

Clock readings, **verbatim urandom draws** (any token/key the test derived from
them is recoverable), the initial and final global `random` state, the pytest
node id, configuration, and a minimal replay fingerprint. Environment names,
environment values, and the hostname are not stored; `TZ`, `PYTHONHASHSEED`,
locale, platform, source hashes, and versions are retained for fidelity checks.

Raw journals are credential-equivalent. Hermetic does not pretend that
redacting entropy preserves exact replay. Instead it uses private atomic files,
value-free credential reports, a fail-closed upload audit, and optional
AES-256-GCM client-side encryption. Never upload the raw journal directory to a
public or plaintext artifact store. Decrypted replay files live only in a
mode-`0700` POSIX temporary directory with mode-`0600` files, or in Windows
paths protected by a current-user-only DACL. They are removed after pytest
exits.

The repository's
[`Cross-runner replay proof`](https://github.com/Therealdk8890/hermetic-sandbox/blob/main/.github/workflows/replay-proof.yml) records a
known-safe synthetic Linux failure, seals its replay-sensitive journal, and
requires fresh Linux, macOS, and Windows jobs to reproduce its clock, random,
UUID, and `secrets` values in under 60 seconds measured from immediately before
artifact download. Its checked-in key is explicitly public canary material;
production keys must be secret and independently generated. The precise claim,
evidence, and non-claims are maintained in
[`REPLAY_PROOF.md`](https://github.com/Therealdk8890/hermetic-sandbox/blob/main/REPLAY_PROOF.md).

## Honest limitations

- **Captured-input boundary**: journals capture Python-level clock calls, global
  `random` state, and Python-level `os.urandom`/`secrets` draws. They do not
  capture ambient environment values, existing file contents, local socket
  responses, subprocess behavior, dependency behavior, or C-extension inputs.
  Exact replay is guaranteed only for the captured inputs in a compatible
  source/runtime environment. Native cross-OS replay is tested for that scope,
  not claimed for arbitrary platform-dependent tests.
- **Threads**: patches are process-global; the virtual clock affects all
  threads, but `threading.Event.wait`/`Condition.wait`/lock timeouts block in C
  against the *real* clock and can't be virtualized. A thread that calls the
  patched (non-blocking) `sleep` in a loop will busy-spin. Multi-threaded
  recording is detected and stamped in the journal; strict replay refuses it.
- **asyncio**: virtual time is not supported. `loop.time()` does follow
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
- **Abrupt termination**: a hard process kill cannot flush a pending journal.
  Ordinary setup/call/teardown failures and best-effort session cleanup are
  covered.

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
