"""Result types mirroring the CLI-JSON.md v1 report shape.

These are carriers, not judges: severity classification and class ordering come
from the Go core's report. Nothing here re-derives, re-sorts, or re-ranks —
the one canonical parser lives in Go (a second implementation is a format
schism waiting for its first disagreement).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple, Union


@dataclass(frozen=True)
class LockResult:
    """A successful lock: the entry surfacelock wrote."""

    name: str
    tools: int
    era: str
    surface_hash: str
    lockfile: str


@dataclass(frozen=True)
class ToolDrift:
    """One tool's classified drift. classes is most severe first, never empty,
    exactly as the Go classifier emitted it."""

    name: str
    classes: Tuple[str, ...]


@dataclass(frozen=True)
class ServerDiff:
    """One server's classified drift (outcome "drift")."""

    severity: str
    era_changed: bool
    old_era: str
    new_era: str
    instructions_changed: bool
    tools: Tuple[ToolDrift, ...]


@dataclass(frozen=True)
class ServerOK:
    """One server verified clean (outcome "ok")."""

    tools: int
    era: str


@dataclass(frozen=True)
class ServerFailure:
    """One server that could not be judged (outcome "transport", "lockfile",
    or "inadmissible"). error is untrusted text: control characters are
    neutralized upstream, but treat it as data, not terminal-safe output."""

    outcome: str
    error: str


ServerResult = Union[ServerOK, ServerDiff, ServerFailure]


@dataclass(frozen=True)
class Report:
    """A verify/diff run's full report: every server processed, each with its
    own verdict. The run-level exit code is the WORST verdict; per-server
    results survive it (a drift beside a transport failure is still here)."""

    verb: str
    lockfile: str
    exit_code: int
    servers: Mapping[str, ServerResult] = field(default_factory=dict)

    @property
    def drifted(self) -> Tuple[str, ...]:
        """Names of servers whose verdict is drift, in name order."""
        return tuple(sorted(n for n, s in self.servers.items() if isinstance(s, ServerDiff)))


def _tool_drift(doc: Mapping[str, Any]) -> ToolDrift:
    return ToolDrift(name=doc["name"], classes=tuple(doc["classes"]))


def _server_result(doc: Mapping[str, Any]) -> ServerResult:
    outcome = doc["outcome"]
    if outcome == "ok":
        return ServerOK(tools=doc["tools"], era=doc["era"])
    if outcome == "drift":
        d = doc["diff"]
        return ServerDiff(
            severity=d["severity"],
            era_changed=d["era_changed"],
            old_era=d["old_era"],
            new_era=d["new_era"],
            instructions_changed=d["instructions_changed"],
            tools=tuple(_tool_drift(t) for t in d["tools"]),
        )
    return ServerFailure(outcome=outcome, error=doc.get("error", ""))


def report_from_doc(doc: Mapping[str, Any]) -> Report:
    """Build a Report from a parsed CLI-JSON.md document (verify/diff)."""
    servers = {name: _server_result(s) for name, s in (doc.get("servers") or {}).items()}
    return Report(verb=doc["verb"], lockfile=doc["file"], exit_code=doc["exit"], servers=servers)


def lock_result_from_doc(doc: Mapping[str, Any]) -> LockResult:
    """Build a LockResult from a parsed CLI-JSON.md document (lock, exit 0)."""
    return LockResult(name=doc["name"], tools=doc["tools"], era=doc["era"],
                      surface_hash=doc["surface_hash"], lockfile=doc["file"])


def report_error_text(doc: Optional[Mapping[str, Any]]) -> Optional[str]:
    """The run-level error string from a report document, if any."""
    if doc is None:
        return None
    err = doc.get("error")
    return err if isinstance(err, str) and err else None
