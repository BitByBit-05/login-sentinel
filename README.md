# Login Sentinel

[![tests](https://github.com/BitByBit-05/login-sentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/BitByBit-05/login-sentinel/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A command-line tool that reads **Linux SSH logs** and **Windows Security event logs**, detects login attacks, and maps each finding to **MITRE ATT&CK**.

It answers the questions a security analyst asks first when reviewing login activity: *Is someone guessing passwords? Is one machine trying every account? Did any of those guesses work?*

```
$ login-sentinel sample_data/auth.log sample_data/windows_security.csv --year 2026

LOGIN SENTINEL REPORT
============================================================
Events analysed : 114 (76 failed, 38 succeeded)
Time range      : 2026-10-12T02:05:00  to  2026-10-13T23:05:30
Unique IPs      : 14    Unique accounts: 23
Lines skipped   : 120 (not login attempts)

Findings: CRITICAL 2  HIGH 4
------------------------------------------------------------
[1] CRITICAL | success_after_failures | MITRE T1078
    'bob' logged in from 192.0.2.99 after 6 failed attempts; credentials may be compromised
    Source IP: 192.0.2.99   Accounts: bob
    Seen: 2026-10-12 22:41:00 to 22:44:40

[2] CRITICAL | success_after_failures | MITRE T1078
    'svc_backup' logged in from 203.0.113.12 after 4 failed attempts; credentials may be compromised
    Source IP: 203.0.113.12   Accounts: svc_backup
    Seen: 2026-10-13 23:02:00 to 23:05:30

[3] HIGH | password_spray | MITRE T1110.003
    12 failed logins across 12 different accounts from 203.0.113.77 in 7 min 20 s
    Source IP: 203.0.113.77   Accounts: admin, alice, bob, deploy (+8 more)
    Seen: 2026-10-12 02:05:00 to 02:12:20
...
```

This is real output from the sample logs (the first 3 of 6 findings). The full report is in [docs/sample_report.md](docs/sample_report.md).

## What it sees

![Bar chart of one day of SSH logins: a few normal logins during the day, and three spikes of failed logins labelled password spray, brute force on root, and bob's password guessed](docs/images/timeline.png)

A normal working day has a handful of successful logins (blue) and the occasional mistyped password. The three orange spikes are the planted attacks, and Login Sentinel reports each one.

## Features

- **Two log sources, one model.** Linux `auth.log` (sshd) and Windows Security events 4624/4625 are converted into the same `LoginEvent`, so every rule works on both.
- **Three detection rules** mapped to MITRE ATT&CK (details below).
- **SQLite storage.** Events and findings are written to SQLite, and the summary statistics are calculated with SQL. Use `--db` to keep the database and query it yourself.
- **Three report formats:** plain text for the terminal, Markdown for tickets and wikis, JSON for other tools.
- **Automation-friendly exit codes.** `--fail-on high` exits with code 1 when serious findings exist, so a scheduled job or pipeline can raise an alert.
- **No dependencies.** It uses only the Python standard library. pytest is needed only for the tests, and matplotlib only to redraw the chart above.
- **51 unit and end-to-end tests with 100% line coverage**, run on Python 3.10–3.13 by GitHub Actions on every push. CI fails if coverage drops below 95%.

## Detection rules

| Rule | Attack it catches | Logic (defaults) | MITRE ATT&CK | Severity |
|------|-------------------|------------------|--------------|----------|
| `brute_force` | Guessing one account's password over and over | ≥ 5 failures for the **same account** from the **same IP** within 10 min | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing | HIGH |
| `password_spray` | Trying a few common passwords against many accounts, which avoids lockouts | ≥ 5 **different accounts** failing from the **same IP** within 10 min | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying | HIGH |
| `success_after_failures` | An attacker's guess finally working | A successful login after ≥ 3 failures for the same account and IP within 10 min | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | CRITICAL |

### How the detection works

`brute_force` and `password_spray` share one function, `find_bursts()` in [`detectors.py`](login_sentinel/detectors.py). It slides a 10-minute **window** along the failed logins, in time order:

```
time ──────────────────────────────────────────────────────────────►
         x  x x  x x x                         x
        [── 10 minutes ──]                    [── 10 minutes ──]
         6 failures → ALERT                    1 failure → ignored
```

Two pointers mark the window. The right pointer adds the next event, and the left pointer moves forward until everything between them fits inside 10 minutes. Then the window is **measured**:

- `brute_force` counts the **failures** in it (for one account from one IP).
- `password_spray` counts the **different accounts** in it (from one IP).

If the measure reaches the threshold, it's an attack. Overlapping windows are merged, so a 6-minute attack with 40 attempts produces **one** finding instead of dozens.

`success_after_failures` is simpler still: whenever a login succeeds, it looks back 10 minutes and counts that account's failures from the same IP.

### What it deliberately does *not* flag

The sample data includes normal behaviour, and the tests check that it stays quiet:

- A user who mistypes their password once or twice and then logs in (`carol`, `dave`)
- An IP making 3 slow attempts spread over two hours (`203.0.113.200`)
- Windows local logons with no network address

False positives cost analysts time, so the defaults are conservative and every threshold is configurable.

## Quick start

```bash
git clone https://github.com/BitByBit-05/login-sentinel.git
cd login-sentinel
pip install -e ".[dev]"

login-sentinel sample_data/auth.log sample_data/windows_security.csv --year 2026
pytest
```

Without installing, `python -m login_sentinel ...` works the same way.

## Run it in VS Code

1. Install [Python 3.10+](https://www.python.org/downloads/) and [VS Code](https://code.visualstudio.com/).
2. Open **`login-sentinel.code-workspace`** (File → Open Workspace from File…). Accept the recommended extensions when VS Code asks.
3. **Terminal → Run Task… → "1. Setup: create .venv and install"**. This creates a virtual environment and installs everything.
4. Press **Ctrl+Shift+P → "Python: Select Interpreter"** and choose the `.venv` one.

After that:

| To… | Do this |
|-----|---------|
| Run the tool on the sample logs | Run and Debug panel (**Ctrl+Shift+D**) → **"Analyze sample logs (text report)"** → **F5** |
| Step through the detection logic | Set a breakpoint in `login_sentinel/detectors.py`, then run the same configuration |
| Run every test | Testing panel (beaker icon) → **Run All Tests**, or **Terminal → Run Task… → "2. Run all tests with coverage"** |
| See which lines the tests cover | **Run Task… → "4. Build HTML coverage report"**, then open `htmlcov/index.html` in a browser |
| Browse the SQLite database | Run **"Analyze sample logs and save SQLite database"**, then click `events.db` (SQLite Viewer extension) |
| Analyse your own log | Run **"Analyze a log file of your choice"** and type the path when asked |

## Testing

```bash
pytest -v --cov
```

| Test file | What it checks | Tests |
|-----------|----------------|------:|
| [`test_parsers.py`](tests/test_parsers.py) | Each log line format, IPv6, skipped lines, the New Year rollover, Windows CSV columns and bad rows | 8 |
| [`test_detectors.py`](tests/test_detectors.py) | The sliding window at, below and outside its thresholds, each rule's edge cases, and false positives that must stay quiet | 17 |
| [`test_storage.py`](tests/test_storage.py) | SQLite schema, SQL summary queries, ordering, and that attacker-controlled log text can't inject SQL | 6 |
| [`test_report.py`](tests/test_report.py) | All three report formats, empty reports, long account lists, attacks that cross midnight | 8 |
| [`test_cli.py`](tests/test_cli.py) | End-to-end runs on the sample logs: exactly the 6 planted attacks are found, plus options, output files and exit codes | 12 |

The end-to-end tests are the strongest guarantee. They run the real command on the sample logs and check that it finds **exactly** the six planted attacks, and nothing from the normal users or the slow probing IP.

The last lines of a full run:

```
TOTAL                           279      0   100%
Required test coverage of 95% reached. Total coverage: 100.00%
============================== 51 passed in 0.35s ==============================
```

## Usage

```bash
# Analyse a real server log. auth.log has no year, so give the year it starts in.
# Reading it usually needs sudo or membership in the "adm" group.
login-sentinel /var/log/auth.log --year 2026

# Markdown report saved to a file
login-sentinel sample_data/auth.log -f markdown -o report.md

# Stricter thresholds, keep the database, and exit 1 if anything HIGH or worse is found
login-sentinel /var/log/auth.log --window 5 --brute-threshold 3 --db events.db --fail-on high
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-f`, `--format` | `text` | `text`, `markdown` or `json` |
| `-o`, `--output` | screen | Write the report to a file |
| `--db` | in memory | SQLite file to keep events and findings in |
| `--year` | current year | Year the auth.log starts in (it rolls over automatically at New Year) |
| `--window` | `10` | Detection window in minutes |
| `--brute-threshold` | `5` | Failures on one account that count as brute force |
| `--spray-threshold` | `5` | Distinct accounts from one IP that count as spraying |
| `--fail-on` | off | Exit code 1 if any finding is at or above this severity |

Exit codes: `0` finished, `1` findings at or above `--fail-on`, `2` bad input.

### Analysing Windows logs

On a Windows machine, open PowerShell **as administrator** and export the last 24 hours of logon events:

```powershell
.\scripts\export_windows_events.ps1 -Hours 24 -Path .\windows_security.csv
login-sentinel .\windows_security.csv
```

The CSV needs the columns `TimeCreated, EventID, TargetUserName, IpAddress, WorkstationName`.

### Querying the database yourself

```bash
login-sentinel sample_data/auth.log --year 2026 --db events.db

sqlite3 events.db "SELECT rule, severity, source_ip FROM findings;"
sqlite3 events.db "SELECT user, COUNT(*) AS failures FROM events WHERE success = 0 GROUP BY user ORDER BY failures DESC LIMIT 5;"
```

## Project structure

```
login_sentinel/
  models.py       LoginEvent, Finding and Severity data classes
  parsers.py      Linux auth.log (regex) and Windows CSV parsers
  detectors.py    Sliding-window detection rules
  storage.py      SQLite schema, inserts and SQL summary queries
  report.py       Text, Markdown and JSON output
  cli.py          Command-line arguments and exit codes
scripts/
  generate_samples.py        Builds the sample logs with planted attacks (fixed seed)
  export_windows_events.ps1  Exports Windows logon events to CSV
  make_chart.py              Draws the chart in this README from the sample log
sample_data/      Sample Linux and Windows logs
tests/            51 pytest tests: parsers, rules, storage, reports, end-to-end CLI
.vscode/          Run configurations, tasks and test settings for VS Code
```

```mermaid
flowchart LR
    A[auth.log] --> P[parsers.py]
    B[Windows CSV] --> P
    P -->|LoginEvent list| D[detectors.py]
    P --> S[(SQLite)]
    D -->|Findings| S
    S -->|SQL summaries| R[report.py]
    D --> R
    R --> O[text / Markdown / JSON]
```

## Sample data and chart

The files in `sample_data/` are generated by `scripts/generate_samples.py` with a fixed random seed. They contain a normal working day plus planted attacks: a brute force on `root`, two password sprays, and two accounts whose passwords get guessed. Every IP address comes from the ranges reserved for documentation ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)) or from private networks, so none belongs to a real host.

The chart near the top is drawn by `scripts/make_chart.py` from the sample log. To redraw it, run `pip install -e ".[charts]"` and then `python scripts/make_chart.py`.

## Limitations

- An attacker who rotates through many IP addresses (a botnet) can spread attempts thin enough to stay under the per-IP thresholds.
- auth.log has no year in its timestamps, so the tool relies on `--year` and New Year rollover detection.
- It analyses log files after the fact rather than watching them live.

## Roadmap

- Rule for one account failing from **many** IPs (distributed brute force)
- Watch mode that follows a log file in real time (`tail -f` style)
- Flag logins from new countries using a GeoIP database
- Account lockout events (Windows 4740)

## License

[MIT](LICENSE)
