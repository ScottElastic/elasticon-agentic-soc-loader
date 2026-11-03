"""Attack / ops scenarios. Each returns a ScenarioResult: the (datastream, doc) events to
index, plus the prebuilt rules expected to fire (rule_id + name) so run.py can report them."""
from __future__ import annotations

from dataclasses import dataclass, field


def ds(dataset: str, namespace: str, metrics: bool = False) -> str:
    """data stream name: {type}-{dataset}-{namespace}."""
    return f"{'metrics' if metrics else 'logs'}-{dataset}-{namespace}"


@dataclass
class ScenarioResult:
    name: str
    events: list[tuple[str, dict]] = field(default_factory=list)
    expected_rules: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # custom-rule / dashboard guidance
    # Plain (non-data-stream) indices this scenario writes to, with explicit mappings —
    # created before bulk indexing so keyword fields work in ES|QL and cleanup.
    index_mappings: dict[str, dict] = field(default_factory=dict)

    def add(self, datastream: str, doc: dict) -> None:
        self.events.append((datastream, doc))

    def expect(self, rule_id: str, name: str) -> None:
        if (rule_id, name) not in self.expected_rules:
            self.expected_rules.append((rule_id, name))

    def note(self, text: str) -> None:
        self.notes.append(text)

    def by_datastream(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for datastream, doc in self.events:
            out.setdefault(datastream, []).append(doc)
        return out
