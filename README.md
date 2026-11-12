# detect-engine

A compact **Sigma-style detection engine** in Python. Write detections as YAML, run them against JSONL logs, get alerts tagged with **MITRE ATT&CK** techniques, and export an **ATT&CK Navigator** layer to see your coverage.

It is intentionally small (about 400 lines) so the whole design can be read in one sitting: rule parsing, a boolean condition parser, field modifiers and a sliding-window correlation engine.

## Features

* Sigma-inspired rules: named selection blocks plus a `condition` such as `parent and child and not trusted`
* Modifiers: `contains`, `startswith`, `endswith`, `re`, `gt/gte/lt/lte`, `all`
* Nested fields with dot notation (`process.command_line`)
* **Correlation**: threshold per group inside a time window (for example 5 failed SSH logins from one IP in 60 s), with counter reset to avoid alert storms
* ATT&CK tags parsed into techniques and tactics; Navigator layer export for alerts or rule coverage
* Rule validation: required keys, valid levels, undefined condition blocks, duplicate IDs
* 7 ready-to-use rules (SSH brute force, encoded PowerShell, Office spawning shells, LSASS access, admin group change, AWS root login, cron persistence)

## Quick start

```bash
pip install -e .
detect-engine run --rules rules --events data/sample_events.jsonl --min-level high
detect-engine validate --rules rules --navigator coverage.json
cat events.jsonl | detect-engine run --rules rules --events - --format json
```

Exit code is `1` when alerts fire, so it works as a gate in pipelines.

## Rule example

```yaml
id: win-office-shell-001
title: Office application spawning a shell
level: critical
tags: [attack.initial_access, attack.t1566.001, attack.execution, attack.t1204.002]
detection:
  parent:
    process.parent_image|endswith: [\winword.exe, \excel.exe, \outlook.exe]
  child:
    process.image|endswith: [\cmd.exe, \powershell.exe, \wscript.exe]
  condition: parent and child
```

A list of values means OR, several fields in one block mean AND.

## Architecture

```
rules/*.yml -> rules.py (parse + validate) -> engine.py (evaluate per event)
                     |                             |
              condition.py (and/or/not)     matcher.py (modifiers)
                                                   |
                                      alerts -> cli.py / navigator.py
```

## Limitations and next steps

This is a learning-grade engine, not a SIEM. It reads JSONL, not live streams, and does not implement the full Sigma spec or field mapping pipelines. Natural extensions: Sigma rule import via pySigma, a Windows EVTX reader, state persistence for correlation, and a Splunk/Elastic query backend.

## Development

```bash
pip install -e .[dev] && pytest -q
```

## License

MIT
