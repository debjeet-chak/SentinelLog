# SentinelLog

SentinelLog is a command-line log analyzer and threat detector for Linux auth logs. It reads `/var/log/auth.log` (or any compatible log file), applies a set of configurable sliding-window detectors, and reports threats — brute force login attempts, suspicious high-volume IPs, repeated sudo failures, and port scan patterns — as a Rich terminal table or structured JSON. It demonstrates TDD-first Python development, a clean layered architecture, and practical defensive security tooling.

---

## Installation

```bash
git clone https://github.com/debjeet-chak/SentinelLog.git
cd SentinelLog
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `sentinel` command is now available in your shell.

---

## Usage

### Basic analysis

```bash
sentinel analyze /var/log/auth.log
```

Parses the log, runs all four detectors, and prints a colour-coded threat table.

### JSON output

```bash
sentinel analyze auth.log --format json
```

Emits a JSON array — one object per threat — suitable for piping into `jq`, logging systems, or SIEM ingestion.

### Custom thresholds

```bash
sentinel analyze auth.log --config custom.yaml
```

Override any detection threshold or whitelist via a YAML config file. Without `--config`, built-in defaults are used (see [Configuration](#configuration)).

---

## Threat Detection

SentinelLog runs four independent detectors. Each uses a **sliding-window algorithm** (two-pointer, O(n)) that scans events sorted by timestamp and finds the densest burst within a configurable time window.

### Brute Force (`brute_force`)

Counts `Failed password` and `Invalid user` SSH events per source IP within a rolling window.

| Default threshold | Behaviour |
|---|---|
| ≥ 5 failures in 60 s | `HIGH` threat |
| ≥ 10 failures in 60 s | Escalated to `CRITICAL` |

### Suspicious IP (`suspicious_ip`)

Counts **all** log events (any type) originating from a single IP. A high total event volume from one source is a reliable indicator of automated reconnaissance, enumeration, or fuzzing — even when no individual event type crosses its own threshold. Legitimate high-volume sources (monitoring hosts, load balancers) should be whitelisted.

| Default threshold | Behaviour |
|---|---|
| ≥ 100 events in 300 s | `MEDIUM` threat |

### Failed Sudo (`failed_sudo`)

Detects repeated `pam_unix(sudo)` authentication failures per user. Uses a `pam_unix(sudo)` context filter to avoid double-counting events that also appear in SSH failure logs.

| Default threshold | Behaviour |
|---|---|
| ≥ 3 failures in 120 s | `HIGH` threat |

### Port Scan (`port_scan`)

Tracks distinct destination ports contacted by a single source IP within a window. A high count of unique ports is a reliable indicator of automated scanning.

| Default threshold | Behaviour |
|---|---|
| ≥ 10 distinct ports in 60 s | `HIGH` threat |

---

## Threat Levels

| Level | Colour | Meaning |
|---|---|---|
| `CRITICAL` | Red | Severe — immediate attention required |
| `HIGH` | Yellow | Significant — investigate promptly |
| `MEDIUM` | Cyan | Notable — monitor or tune threshold |
| `INFO` | White | Informational |

---

## Configuration

Copy the example config and edit to suit your environment:

```bash
cp config.example.yaml my-config.yaml
sentinel analyze /var/log/auth.log --config my-config.yaml
```

```yaml
thresholds:
  brute_force:
    max_failures: 5        # failed attempts before flagging
    window_seconds: 60
  suspicious_ip:
    max_requests: 100
    window_seconds: 300
  failed_sudo:
    max_failures: 3
    window_seconds: 120
  port_scan:
    min_distinct_ports: 10
    window_seconds: 60

whitelist:
  ips: []       # never flag these — supports exact IPs and CIDR ranges
  users: []     # exclude these usernames from sudo alerts
```

**Whitelist examples:**

```yaml
whitelist:
  ips:
    - 10.0.0.1          # exact IP
    - 192.168.1.0/24    # CIDR subnet
  users:
    - deploy
    - monitoring
```

Invalid entries (malformed IPs or CIDRs) emit a warning and are skipped; valid entries are still loaded.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Analysis complete — no threats detected |
| `1` | Analysis complete — one or more threats detected |
| `2` | Error — config file not found or invalid |

---

## Use in Scripts

The exit code makes SentinelLog easy to integrate into automated pipelines:

```bash
#!/usr/bin/env bash

sentinel analyze /var/log/auth.log --format json > /tmp/threats.json
EXIT=$?

if [ $EXIT -eq 2 ]; then
    echo "ERROR: SentinelLog failed to run" >&2
    exit 1
fi

if [ $EXIT -eq 1 ]; then
    echo "Threats detected — sending alert"
    curl -s -X POST https://alerts.example.com/hook \
        -H "Content-Type: application/json" -d @/tmp/threats.json
fi

if [ $EXIT -eq 0 ]; then
    echo "Clean — no threats found"
fi
```

---

## How It's Built

### Test-Driven Development

Every module was built RED → GREEN → REFACTOR. Tests were written before implementation; the test suite never saw green until the implementation was complete. The project ships with 78 tests covering models, config loading, all four detectors, the parser, the CLI, and the reporter.

### Coverage Gate

`pyproject.toml` enforces `--cov-fail-under=80`. The suite currently runs at **97% coverage** — the CI step fails if it drops below 80%.

### Security Review

Detectors are hardened against untrusted log input:

- `yaml.safe_load` — never `yaml.load`
- All regexes compiled at module level, never inside loops
- No shell surfaces — zero `subprocess`, `os.system`, or `shell=True`
- Config values validated at load time with field-name error messages
- IP/CIDR matching uses Python's `ipaddress` stdlib, not string comparison

### Layered Architecture

```
cli.py            ← Click entrypoint, wires everything together
  ├── config.py   ← YAML loading + validation
  ├── parsers/    ← BaseParser → AuthLogParser
  ├── detectors/  ← BaseDetector → BruteForce, FailedSudo, SuspiciousIP, PortScan
  └── reporter.py ← render_table() → str, render_json() → str
```

Each layer is independently testable. The reporter uses `Console(file=StringIO())` so output can be asserted on in tests without subprocess or stdout capture hacks.

### Workflow

Built using the [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) agent harness: `/plan` → `/tdd` → `/code-review` → `/security-scan` at each phase.

---

## Requirements

- Python 3.11+
- Linux with `/var/log/auth.log` (tested on Ubuntu 22.04). macOS uses the Unified Log system and does not produce an `auth.log` file; use a captured log file instead.
- [click](https://click.palletsprojects.com/) ≥ 8.1
- [rich](https://github.com/Textualize/rich) ≥ 13.0
- [pyyaml](https://pyyaml.org/) ≥ 6.0

---

## License

MIT
