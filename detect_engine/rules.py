from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .condition import compile_condition, referenced_names

LEVELS = ["informational", "low", "medium", "high", "critical"]
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass
class Correlation:
    group_by: list[str]
    threshold: int
    window_seconds: int


@dataclass
class Rule:
    id: str
    title: str
    description: str
    level: str
    tags: list[str]
    detections: dict[str, dict]
    condition_text: str
    condition: Callable[[dict[str, bool]], bool] = field(repr=False)
    correlation: Correlation | None = None

    @property
    def techniques(self) -> list[str]:
        out = []
        for t in self.tags:
            m = _TECH.match(t)
            if m:
                out.append(m.group(1).upper())
        return out

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags if t.startswith("attack.") and not _TECH.match(t)]


def parse_rule(data: dict[str, Any]) -> Rule:
    for key in ("id", "title", "level", "detection"):
        if key not in data:
            raise ValueError(f"Rule missing required key: {key}")
    if data["level"] not in LEVELS:
        raise ValueError(f"Rule {data['id']}: invalid level {data['level']!r}")
    det = dict(data["detection"])
    cond = det.pop("condition", None)
    if not cond:
        raise ValueError(f"Rule {data['id']}: detection.condition is required")
    missing = referenced_names(cond) - set(det)
    if missing:
        raise ValueError(f"Rule {data['id']}: condition references undefined blocks {sorted(missing)}")
    corr = None
    if "correlation" in data:
        c = data["correlation"]
        corr = Correlation(list(c["group_by"]), int(c["threshold"]), int(c["window_seconds"]))
    return Rule(
        id=data["id"], title=data["title"], description=data.get("description", ""),
        level=data["level"], tags=list(data.get("tags", [])), detections=det,
        condition_text=cond, condition=compile_condition(cond), correlation=corr,
    )


def load_rules(path: str | Path) -> list[Rule]:
    p = Path(path)
    files = [p] if p.is_file() else sorted(list(p.glob("*.yml")) + list(p.glob("*.yaml")))
    rules = []
    for f in files:
        rules.append(parse_rule(yaml.safe_load(f.read_text(encoding="utf-8"))))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate rule ids: {sorted(dupes)}")
    return rules
