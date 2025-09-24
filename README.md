# AnyDesk Live Log Monitor

## Overview
The **AnyDesk Live Log Monitor** is a Python utility that streams AnyDesk session activity in real time and emits structured events that downstream applications (for example, an Electron dashboard) can consume. It targets environments where quick detection of inbound remote connections is critical and provides a consistent JSON-like event format on STDOUT.

Key capabilities include:

- Auto-detecting the correct AnyDesk log file across Windows, macOS, and Linux.
- Historical log replay to catch activity that happened shortly before the monitor was started.
- Immediate `user-connected` and `connection-request` events when a remote session begins.
- Rich event metadata covering authentication, session lifecycle, networking, and shutdown signals.
- Optional debug instrumentation for deeper diagnostics.

---

## Quick Start

### Requirements
- Python 3.10 or later (the script relies on the standard library only).
- Access to AnyDesk logs on the host machine.

### Installation
\`\`\`bash
# clone or download this repository
python3 --version       # verify Python availability
\`\`\`

### Launch the monitor
\`\`\`bash
python3 scripts/anydesk-live-monitor-fixed.py
\`\`\`

By default the monitor:
- Auto-locates the active AnyDesk log file.
- Performs a historical sweep of the previous 15 minutes.
- Continues tailing the log file and emitting events until interrupted.

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--log-path, -l` | Explicit path to an AnyDesk log file when auto-detection is insufficient. | Auto-detect |
| `--find-logs` | Lists all discoverable log files and exits; useful for verifying paths. | Disabled |
| `--check-history` | Enables historical scanning before live monitoring starts. | Enabled |
| `--no-history` | Shortcut to disable historical scanning even if `--check-history` is present. | Disabled |
| `--history-minutes` | Sets the time window (in minutes) for the historical scan. | `15` |
| `--debug` | Emits verbose debug information about timestamp parsing and file handling. | Disabled |

> **Note:** The script interprets timestamps using the machine’s local timezone rather than forcing UTC conversion, which avoids false positives in historical mode.

---

## Event Stream

Each line the monitor prints follows the format:

\`\`\`
<event-type>[DDD]{...JSON payload...}
\`\`\`

This makes it easy to split on the `"[DDD]"` delimiter and parse the trailing JSON blob.

### Core Events

| Event | Trigger | Payload Highlights |
|-------|---------|--------------------|
| `monitor-initialized` | Script startup | `log_path`, `log_exists`, `check_historical`, `historical_minutes` |
| `historical-scan-started` | Historical sweep begins | `minutes_checked`, `events_found` |
| `historical-scan-completed` | Sweep finished | `events_processed` |
| `historical-scan-no-events` | No recent entries found | `lines_processed`, `found_old_data` |
| `connection-request` | AnyDesk reports “Accept request from …” | `anydesk_id`, `connection_type`, `is_historical` |
| `user-connected` | Synchronous duplicate of `connection-request` for immediate downstream handling | Same as above |
| `client-identified` | Client fingerprint/IP discovered | `client_id`, `fingerprint`, `ip_address?` |
| `authentication-success` | Authentication success log line | `auth_method`, `profile?` |
| `session-started` / `session-ended` | Session lifecycle | `features?`, `reason` |
| `network-connected` | Relay connection established | `connection_type` |
| `start-app`, `app-shutdown` | AnyDesk runtime status | `version?`, general metadata |
| `ERROR` | Any runtime failure | `error`, `message` |

Each payload includes:
- `timestamp`: script emission time in ISO-8601.
- `log_timestamp`: original log timestamp.
- `is_historical`: `true` if sourced during the preflight sweep.

---

## Historical Scan Behaviour

- Reads the last ~50 KB of the log and processes entries in reverse order to avoid replaying stale sessions.
- Stops reading as soon as it finds a timestamp older than the cutoff (`now - history_minutes`).
- Ensures that only relevant events (e.g., last 15 minutes) are replayed when the script starts, preventing duplicate alerts from previous days.

You can disable the scan entirely with `--no-history` or change the window via `--history-minutes`.

---

## Integration Tips

1. **Electron / Node consumers:** split the STDOUT string on `"[DDD]"`, then `JSON.parse` the right-hand side.
2. **Systemd services:** wrap the script in a unit file and use `Restart=always` to keep monitoring after crashes.
3. **Security teams:** tie the `user-connected` event to alerting systems (email, Slack, SIEM) for rapid notification.
4. **Data logging:** persist events to a database or log aggregator to build a searchable history of remote access.

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| `log_file_not_found` in `ERROR` events | AnyDesk log path cannot be resolved | Run with `--find-logs` to discover the correct file. Pass the result via `--log-path`. |
| Historical scan returns zero events despite recent activity | Log timestamps may precede `history_minutes` cutoff | Increase `--history-minutes` to widen the window. |
| Events appear out of order | Downstream consumer processing order incorrectly | Sort by `log_timestamp` if strict ordering is required. |
| No `user-connected` events triggered | Connection requests may be filtered | Ensure AnyDesk logging is enabled and watch for “Accept request from …” entries. |

Enable `--debug` to inspect timestamp extraction and parsing if the historical cutoff behaves unexpectedly.

---

## Development Notes

- The script lives at [`scripts/anydesk-live-monitor-fixed.py`](scripts/anydesk-live-monitor-fixed.py).
- Uses only the Python standard library, making distribution straightforward.
- Designed to run indefinitely until interrupted (Ctrl+C), emitting `monitoring-stopped` with reason `user_interrupt`.

---

## License
This project currently ships without an explicit license. Add one if redistribution is required.
