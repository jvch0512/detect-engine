"""Field matching with Sigma-like modifiers: field|contains, |startswith, |endswith, |re, |gt, |lt, |all."""
from __future__ import annotations

import re
from typing import Any

_MODS = {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "all"}


def _get(event: dict, field: str) -> Any:
    cur: Any = event
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_one(value: Any, mod: str | None, expected: Any) -> bool:
    if value is None:
        return False
    if mod in ("gt", "gte", "lt", "lte"):
        try:
            v, e = float(value), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": v > e, "gte": v >= e, "lt": v < e, "lte": v <= e}[mod]
    s, e = str(value).lower(), str(expected).lower()
    if mod == "contains":
        return e in s
    if mod == "startswith":
        return s.startswith(e)
    if mod == "endswith":
        return s.endswith(e)
    if mod == "re":
        return re.search(str(expected), str(value), re.IGNORECASE) is not None
    return s == e


def match_selection(event: dict, selection: dict) -> bool:
    """All fields in a selection must match (AND). A list of values matches if ANY matches (OR),
    unless the |all modifier is used."""
    for key, expected in selection.items():
        field, *mods = key.split("|")
        unknown = set(mods) - _MODS
        if unknown:
            raise ValueError(f"Unknown modifier(s) {unknown} in {key!r}")
        use_all = "all" in mods
        mod = next((m for m in mods if m != "all"), None)
        value = _get(event, field)
        options = expected if isinstance(expected, list) else [expected]
        results = [_match_one(value, mod, opt) for opt in options]
        ok = all(results) if use_all else any(results)
        if not ok:
            return False
    return True
