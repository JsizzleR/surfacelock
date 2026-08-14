"""surfacelock — programmatic lock/verify/diff of MCP tool surfaces.

A thin, typed layer over the surfacelock CLI (bundled in this wheel). The Go
core is the one canonical parser: these bindings drive it as a subprocess and
read its versioned machine report (CLI-JSON.md) — they never reimplement
canonicalization, hashing, or drift classification, and they add no judgment
of their own to the severity model.

    import surfacelock

    entry = surfacelock.lock("https://example.com/mcp", lockfile="tools.lock")
    try:
        surfacelock.verify(lockfile="tools.lock")
    except surfacelock.DriftError as e:
        for name in e.report.drifted:
            print(name, e.report.servers[name].severity)

Errors are typed on the CLI's exit-code contract, so the remedy can be keyed
on the exception type: DriftError (review, then `surfacelock pin`),
TransportError (unreachable server), LockfileError (bad artifact),
InadmissibleSurfaceError (no verdict can exist), UsageError (fix the call).
Accepting drift (`pin`) is deliberately not in this API: a re-lock is a
reviewed VCS diff, a human act.
"""

from __future__ import annotations

from typing import Mapping, Optional, Sequence, Union

from ._errors import (
    DriftError,
    InadmissibleSurfaceError,
    LockfileError,
    SurfacelockError,
    TransportError,
    UsageError,
)
from ._run import raise_for, run_verb
from ._types import (
    LockResult,
    Report,
    ServerDiff,
    ServerFailure,
    ServerOK,
    ServerResult,
    ToolDrift,
    lock_result_from_doc,
    report_from_doc,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "lock",
    "verify",
    "diff",
    "LockResult",
    "Report",
    "ServerDiff",
    "ServerFailure",
    "ServerOK",
    "ServerResult",
    "ToolDrift",
    "SurfacelockError",
    "DriftError",
    "TransportError",
    "LockfileError",
    "InadmissibleSurfaceError",
    "UsageError",
    "__version__",
]

Target = Union[str, Sequence[str]]


def _env_args(env: Optional[Mapping[str, str]]) -> list:
    if not env:
        return []
    out = []
    for k, v in env.items():
        if not k or "=" in k:
            raise UsageError(f"invalid env key {k!r}")
        out += ["--env", f"{k}={v}"]
    return out


def _target_args(target: Target) -> list:
    if isinstance(target, str):
        return ["--url", target]
    argv = list(target)
    if not argv or not all(isinstance(a, str) for a in argv):
        raise UsageError("stdio target must be a non-empty sequence of strings")
    return ["--", *argv]


def lock(
    target: Target,
    *,
    lockfile: str = "tools.lock",
    name: Optional[str] = None,
    timeout: float = 60.0,
    offer: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    binary: Optional[str] = None,
    process_budget: Optional[float] = None,
) -> LockResult:
    """Capture a server's tool surface into the lockfile (new entry only).

    target: a Streamable HTTP URL (str) or a stdio command (sequence of str).
    Refuses an existing entry name — accepting a changed surface is `pin`'s
    job, and pin stays a CLI/VCS act by design.
    """
    args = ["--file", lockfile]
    if name:
        args += ["--name", name]
    if offer:
        args += ["--offer", offer]
    args += _env_args(env)
    args += _target_args(target)
    code, doc, stderr = run_verb("lock", args, binary=binary, timeout=timeout,
                                 process_budget=process_budget)
    if code != 0:
        raise_for(code, doc, stderr)
    return lock_result_from_doc(doc)


def verify(
    *,
    lockfile: str = "tools.lock",
    name: Optional[str] = None,
    timeout: float = 60.0,
    env: Optional[Mapping[str, str]] = None,
    binary: Optional[str] = None,
    process_budget: Optional[float] = None,
) -> Report:
    """Re-fetch every entry (or one named entry) and fail on drift.

    Returns the clean Report; raises DriftError on drift, and the other typed
    errors on harder failures. Whatever exception is raised, its .report
    carries every per-server verdict the run produced — a drift found beside
    a transport failure is never lost to the exception type.
    """
    return _compare("verify", lockfile, name, timeout, env, binary, process_budget,
                    raise_on_drift=True)


def diff(
    *,
    lockfile: str = "tools.lock",
    name: Optional[str] = None,
    timeout: float = 60.0,
    env: Optional[Mapping[str, str]] = None,
    binary: Optional[str] = None,
    process_budget: Optional[float] = None,
) -> Report:
    """Like verify, but drift is the expected answer, not a failure: returns a
    Report whose ServerDiff entries are severity-classified (by the Go core),
    empty of diffs when nothing drifted. Harder failures still raise."""
    return _compare("diff", lockfile, name, timeout, env, binary, process_budget,
                    raise_on_drift=False)


def _compare(
    verb: str,
    lockfile: str,
    name: Optional[str],
    timeout: float,
    env: Optional[Mapping[str, str]],
    binary: Optional[str],
    process_budget: Optional[float],
    *,
    raise_on_drift: bool,
) -> Report:
    args = ["--file", lockfile]
    if name:
        args += ["--name", name]
    args += _env_args(env)
    code, doc, stderr = run_verb(verb, args, binary=binary, timeout=timeout,
                                 process_budget=process_budget)
    report = report_from_doc(doc)
    if code == 0 or (code == 1 and not raise_on_drift):
        return report
    raise_for(code, doc, stderr, report=report)
    raise AssertionError("unreachable")
