from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

from .matcher import _get, match_selection
from .rules import Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    timestamp: str
    event: dict
    group: str = ""
    count: int = 1

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _ts(event: dict) -> float:
    raw = event.get("timestamp") or event.get("@timestamp")
    if raw is None:
        return 0.0
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()


def rule_matches(rule: Rule, event: dict) -> bool:
    env = {name: match_selection(event, sel) for name, sel in rule.detections.items()}
    return rule.condition(env)


def run(rules: list[Rule], events: Iterable[dict]) -> Iterator[Alert]:
    """Evaluate events in order. Simple rules alert per event. Correlation rules alert once the
    threshold is reached inside a sliding window, then reset that group's counter to avoid alert storms."""
    windows: dict[tuple[str, str], deque] = defaultdict(deque)
    for event in events:
        for rule in rules:
            if not rule_matches(rule, event):
                continue
            base = dict(
                rule_id=rule.id, title=rule.title, level=rule.level, techniques=rule.techniques,
                tactics=rule.tactics, timestamp=str(event.get("timestamp", "")), event=event,
            )
            if rule.correlation is None:
                yield Alert(**base)
                continue
            c = rule.correlation
            group = "|".join(str(_get(event, f)) for f in c.group_by)
            dq = windows[(rule.id, group)]
            now = _ts(event)
            dq.append(now)
            while dq and now - dq[0] > c.window_seconds:
                dq.popleft()
            if len(dq) >= c.threshold:
                yield Alert(**base, group=group, count=len(dq))
                dq.clear()
