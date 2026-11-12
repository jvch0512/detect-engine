import json
from pathlib import Path

import pytest

from detect_engine import engine
from detect_engine.condition import compile_condition
from detect_engine.matcher import match_selection
from detect_engine.rules import load_rules, parse_rule

ROOT = Path(__file__).parent.parent
RULES = load_rules(ROOT / "rules")
EVENTS = [json.loads(l) for l in (ROOT / "data/sample_events.jsonl").read_text().splitlines() if l.strip()]


def ids(alerts):
    return [a.rule_id for a in alerts]


def test_condition_precedence_and_not():
    f = compile_condition("a and b or not c")
    assert f({"a": True, "b": True, "c": True})
    assert f({"a": False, "b": False, "c": False})
    assert not f({"a": True, "b": False, "c": True})


def test_condition_parentheses():
    f = compile_condition("a and (b or c)")
    assert f({"a": True, "c": True}) and not f({"a": False, "b": True})


@pytest.mark.parametrize("bad", ["a and", "(a", "a b", "and a"])
def test_condition_errors(bad):
    with pytest.raises(ValueError):
        compile_condition(bad)


def test_modifiers():
    ev = {"p": {"cmd": "Powershell -ENC abc"}, "n": 7}
    assert match_selection(ev, {"p.cmd|contains": "-enc"})
    assert match_selection(ev, {"p.cmd|startswith": "powershell"})
    assert match_selection(ev, {"n|gt": 5})
    assert not match_selection(ev, {"n|lt": 5})
    assert match_selection(ev, {"p.cmd|contains|all": ["power", "enc"]})
    assert not match_selection(ev, {"p.cmd|contains|all": ["power", "zzz"]})
    with pytest.raises(ValueError):
        match_selection(ev, {"p.cmd|bogus": "x"})


def test_bruteforce_fires_once_for_attacker_not_for_normal_user():
    alerts = list(engine.run(RULES, EVENTS))
    brute = [a for a in alerts if a.rule_id == "ssh-bruteforce-001"]
    assert len(brute) == 1 and brute[0].group == "203.0.113.50" and brute[0].count == 5


def test_all_expected_detections_present():
    got = set(ids(engine.run(RULES, EVENTS)))
    assert {"win-ps-encoded-001", "win-office-shell-001", "win-lsass-dump-001",
            "win-admin-add-001", "aws-root-login-001", "lnx-cron-persist-001"} <= got


def test_lsass_trusted_source_is_filtered():
    lsass = [a for a in engine.run(RULES, EVENTS) if a.rule_id == "win-lsass-dump-001"]
    assert len(lsass) == 1 and "procdump" in lsass[0].event["source"]["image"]


def test_benign_events_do_not_alert():
    assert list(engine.run(RULES, [{"timestamp": "2026-03-01T13:05:00Z", "process": {"name": "ls", "command_line": "ls -la"}}])) == []


def test_window_expiry_resets_count():
    evs = [{"timestamp": f"2026-03-01T10:{m:02d}:00Z", "service": "sshd", "outcome": "failure", "src_ip": "1.1.1.1"} for m in range(0, 10)]
    assert list(engine.run(RULES, evs)) == []  # 1 failure per minute never reaches 5 in 60s


def test_rule_validation():
    base = {"id": "x", "title": "t", "level": "high", "detection": {"a": {"f": 1}, "condition": "a and missing"}}
    with pytest.raises(ValueError, match="undefined"):
        parse_rule(base)
    base["detection"]["condition"] = "a"
    base["level"] = "scary"
    with pytest.raises(ValueError, match="invalid level"):
        parse_rule(base)


def test_techniques_and_tactics_extracted():
    r = next(r for r in RULES if r.id == "win-ps-encoded-001")
    assert "T1059.001" in r.techniques and "execution" in r.tactics
