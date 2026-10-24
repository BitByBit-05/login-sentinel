# Login Sentinel Report

- **Events analysed:** 114 (76 failed, 38 succeeded)
- **Time range:** 2026-10-12T02:05:00 to 2026-10-13T23:05:30
- **Unique IPs:** 14 · **Unique accounts:** 23
- **Lines skipped:** 120
- **Findings:** 2 critical, 4 high

## Findings

| # | Severity | Rule | MITRE | Source IP | Accounts | Events | First seen |
|---|----------|------|-------|-----------|----------|-------:|------------|
| 1 | CRITICAL | `success_after_failures` | T1078 | 192.0.2.99 | bob | 7 | 2026-10-12 22:41 |
| 2 | CRITICAL | `success_after_failures` | T1078 | 203.0.113.12 | svc_backup | 5 | 2026-10-13 23:02 |
| 3 | HIGH | `password_spray` | T1110.003 | 203.0.113.77 | admin, alice, bob, deploy (+8 more) | 12 | 2026-10-12 02:05 |
| 4 | HIGH | `brute_force` | T1110.001 | 203.0.113.45 | root | 40 | 2026-10-12 03:14 |
| 5 | HIGH | `brute_force` | T1110.001 | 192.0.2.99 | bob | 6 | 2026-10-12 22:41 |
| 6 | HIGH | `password_spray` | T1110.003 | 198.51.100.200 | a.patel, administrator, guest, helpdesk (+4 more) | 8 | 2026-10-13 01:30 |

## Top source IPs by failed logins

| Source IP | Failed logins | Accounts tried |
|-----------|--------------:|---------------:|
| 203.0.113.45 | 40 | 1 |
| 203.0.113.77 | 12 | 12 |
| 198.51.100.200 | 8 | 8 |
| 192.0.2.99 | 6 | 1 |
| 203.0.113.12 | 4 | 1 |
