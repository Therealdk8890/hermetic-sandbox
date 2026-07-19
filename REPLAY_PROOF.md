# Hermetic replay proof

This document defines the commercial claims as testable release gates. It
deliberately separates captured Python-level inputs from ambient inputs that
Hermetic does not record.

## Gate 1: CI journal replays on a developer machine

**Proven scope:** Python-level wall/monotonic/performance clock reads, the global
`random` stream, and Python-level `os.urandom` consumers such as `uuid4` and
`secrets`, when the source, test file, Python, Hermetic, pytest, hash seed, and
other fatal fingerprint fields are compatible.

Strict journal v2 replay now enforces:

- one global cross-source event order;
- no missing or extra clock/entropy events;
- matching entropy request lengths;
- matching final global `random` state;
- complete setup, call, and teardown capture;
- rejection of event-cap overflow and cross-thread recording;
- fatal runtime/source mismatches, with explicit platform/locale warnings.

Current direct evidence:

- The full serial and xdist suites exercise record/replay, setup/call/teardown
  failures, relocation, retry bookkeeping, and strict divergence.
- A Linux CPython 3.13.12 container recorded the synthetic proof failure in
  0.330 seconds. The journal was moved to macOS CPython 3.13.12 and replayed
  every captured value exactly in 0.549 seconds.
- `.github/workflows/replay-proof.yml` captures clocks, the global `random`
  stream, `uuid4`, and `secrets`, seals the replay-sensitive journal, and
  repeats the artifact handoff from Linux into fresh Linux, macOS, and Windows
  jobs. It fails unless every value matches and the interval from immediately
  before artifact download through completed replay is under 60 seconds. The
  workflow key is intentionally public synthetic canary material, not a
  production secret.

**Not claimed:** arbitrary environment values, pre-existing file contents,
local-service responses, C-extension entropy/time, dependency behavior,
subprocesses, or platform-specific behavior. Those inputs are fingerprinted or
documented where possible, but they are not captured.

## Gate 2: the journal upload path does not expose secrets

Raw journals are sensitive by design. Exact replay requires verbatim entropy
and predictive random state, so “raw journals never contain secrets” would be a
false guarantee.

The enforceable guarantee is:

> Hermetic refuses plaintext upload of replay-sensitive journals, refuses
> malformed or credential-bearing metadata even when encryption is requested,
> and provides authenticated client-side encryption before transfer.

The implementation:

- writes journals and indexes atomically as mode `0600` on POSIX;
- protects raw journals, indexes, sealed journals, and decrypted replay paths
  on Windows with a verified one-entry DACL granting only the current user full
  control, and fails closed if that postcondition cannot be verified;
- resists pre-planted temporary-file symlinks;
- uses opaque journal filenames;
- omits environment names/values, hostname, and CPU count;
- drops broad secret-prone variables under `scrub_env=True`;
- scans metadata for common credential formats and current sensitive
  environment values without rendering matches;
- blocks plaintext replay data with `hermetic journal inspect`;
- seals approved data with AES-256-GCM through the optional `secure` extra;
- authenticates the envelope header and ciphertext, rejecting wrong keys and
  tampering;
- decrypts only into a mode-`0700` POSIX temporary directory with mode-`0600`
  files, or into Windows paths with a current-user-only DACL, removes journal
  keys from the pytest environment, and deletes plaintext after replay.

## Gate 3: failed check to local replay takes under one minute

The slow path has been removed:

- pytest emits a portable `python -m hermetic replay <directory> --test ...`
  command instead of a runner-specific absolute journal path;
- `hermetic replay` accepts a journal, relocated `index.json`, plaintext
  directory, or sealed directory;
- it selects the recorded test and restores `PYTHONHASHSEED` automatically;
- multiple failures are selectable by node id;
- sealed artifacts decrypt transparently and clean themselves up.

Measured replay after artifact relocation is 0.549 seconds on this Mac. The
checked-in GitHub workflow enforces a 60-second ceiling from immediately before
artifact download through completed exact replay. The remaining evidence step
is a real pushed GitHub run; no local test can truthfully prove GitHub service
latency.

## Reproduce locally

```bash
export HERMETIC_JOURNAL_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PYTHONHASHSEED=0 python -m pytest -q
PYTHONHASHSEED=0 python -m pytest -q -n 2

python .github/replay-proof/record.py
python .github/replay-proof/verify.py .hermetic-proof
```

For a sensitive journal:

```bash
pip install '.[secure]'

# URL-safe base64 for exactly 32 random bytes; store it as a CI secret and in
# the team's password manager.
export HERMETIC_JOURNAL_KEY='...'

python -m hermetic journal seal .hermetic-journals/ \
  --output .hermetic-sealed-journals/
python -m hermetic replay .hermetic-sealed-journals/
```
