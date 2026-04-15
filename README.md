# Prithvi

**Static security scanner for Dockerfiles. No image pulls. No CVE database. No network.**

```
$ prithvi scan Dockerfile
[CRITICAL] PR006  (line 3): Possible hard-coded secret in ENV instruction
         → Move to a build arg sourced from the CI secret store, or mount at runtime.
[    HIGH] PR004  (line 2): Remote installer piped straight to a shell (`curl ... | sh`)
         → Download, verify checksum, *then* execute. Pipes hide supply-chain swaps.
[    HIGH] PR002  (line 4): Image ends as root (no non-root USER set)
         → Add `RUN adduser -D app && USER app` (or similar) before the final CMD.
[  MEDIUM] PR001  (line 1): FROM 'python:latest' uses the :latest tag
         → Pin a specific version so builds are reproducible.
[     LOW] PR003  (line 4): apt-get install without clearing /var/lib/apt/lists
         → Append `&& rm -rf /var/lib/apt/lists/*` to the same RUN so the layer ships trim.

5 findings: 1 low, 1 medium, 2 high, 1 critical
```

*पृथ्वी — the earth.*

Prithvi catches the 80% of container security mistakes that live in
your Dockerfile itself — **before** the image ever hits a registry and
before any CVE scanner has something to grep. It's a fast, deterministic
linter with actionable hints, designed to run as a pre-commit hook or
in CI on every PR.

## Install

```bash
pip install -e .
```

Python ≥ 3.10. Stdlib only.

## Usage

```bash
prithvi scan Dockerfile                          # human-readable
prithvi scan Dockerfile --min high               # hide low / medium
prithvi scan Dockerfile --fail-on medium         # exit 1 if any medium+ found
prithvi scan Dockerfile --json                   # machine-readable
```

Exit codes:
- `0` — no findings at or above `--fail-on` severity (default: **high**).
- `1` — at least one finding at or above the fail threshold.
- `2` — couldn't read the file.

Wire it into a pre-commit hook or GitHub Action for free Dockerfile
hygiene on every change.

## The rules

| ID    | Severity | What it catches                                              |
| ----- | -------- | ------------------------------------------------------------ |
| PR001 | medium   | `FROM image` or `FROM image:latest` — non-reproducible build |
| PR002 | high     | Image ends as root (no `USER` set or last `USER` is `root`)  |
| PR003 | low      | `apt-get install` without cache cleanup / `apk add` without `--no-cache` |
| PR004 | high     | Remote installer piped to a shell (`curl ... \| sh`)         |
| PR005 | low/med  | `ADD` used where `COPY` would do (and `ADD <url>` for fetches) |
| PR006 | critical | Hard-coded password / API key / token in `ENV`/`ARG`/`RUN`   |
| PR007 | medium   | `sudo` inside a `RUN` — the builder is already root          |

Every rule ships with a concrete fix in the `hint:` line.

## Python API

```python
from prithvi import Scanner, scan_dockerfile, Severity

findings = scan_dockerfile("Dockerfile")
for f in findings:
    if f.severity == Severity.CRITICAL:
        print(f.pretty())
```

## Design

- **Rule-based, deterministic.** Every check is a pure function of the
  parsed Dockerfile. Same input → same findings, no flakiness.
- **No network calls.** Runs in air-gapped CI, offline laptops, and
  your pre-commit hook without asking permission.
- **Line-continuation aware.** Multi-line `RUN` blocks with `\\`
  continuations are joined before rule evaluation; findings still
  reference the starting line.
- **Adding a rule is one function.** See `_rule_*` helpers in `core.py`;
  add your function to the `RULES` tuple.

## Not in scope

Prithvi is deliberately a **Dockerfile** scanner, not an image scanner.
For CVEs in installed packages, use Trivy, Grype, or your cloud
provider's scanner. For runtime behaviour (seccomp profiles, network
policies), use Falco / OPA. Prithvi plugs into the earliest possible
layer: the source text your engineers actually author.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest    # 15 tests, < 1s
```

## License

MIT.
