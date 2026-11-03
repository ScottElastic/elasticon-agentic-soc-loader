"""Storyline clock.

Scenario events carry a fabricated @timestamp (the storyline's clock) but the Fleet final
pipeline stamps event.ingested = actual write time. Since ~88% of prebuilt rules key off
event.ingested (docs/detection-rules/prebuilt-rules-management.md §3), scenario events fire
on the next rule run regardless of @timestamp. The exceptions are the few no-override rules
(e.g. the SSH-brute-force EQL sequence) which use @timestamp — so scenarios default their
base time to "now" and lay stages out over the preceding minutes, keeping everything inside
rule look-back windows for a live demo.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_ms(dt: datetime) -> str:
    """ISO-8601 with millisecond precision and a trailing Z (system/K8s/endpoint style)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def iso_s(dt: datetime) -> str:
    """ISO-8601 truncated to whole seconds with a trailing Z (CloudTrail eventTime style)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ct(dt: datetime) -> str:
    """CloudTrail @timestamp style: whole seconds but rendered with .000 millis."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Timeline:
    """A moving cursor for laying out a time-ordered event chain.

    tl = Timeline()                 # base = now - 12 min by default
    t0 = tl.at(0)                   # base
    t1 = tl.advance(30)             # +30s, returns new cursor time
    """

    def __init__(self, base: datetime | None = None, start_offset_s: int = -720):
        self.base = (base or now_utc()) + timedelta(seconds=start_offset_s)
        self.cursor = self.base

    def at(self, offset_s: float) -> datetime:
        return self.base + timedelta(seconds=offset_s)

    def advance(self, seconds: float) -> datetime:
        self.cursor = self.cursor + timedelta(seconds=seconds)
        return self.cursor
