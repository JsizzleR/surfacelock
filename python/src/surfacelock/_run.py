"""Running the CLI and mapping its CLI-JSON.md v1 report to Python values.

The exception TYPE is keyed on the exit code (the SPEC.md §9 contract) and the
payload on the parsed report — never on human output. The bindings refuse a
report whose surfacelock_json version they do not implement: a silent
best-effort parse of a future shape would be a wrong answer delivered
confidently.
"""

from __future__ import annotations

import json
import math
import subprocess
from typing import Any, List, Mapping, Optional, Tuple

from ._bin import find_binary
from ._errors import EXIT_ERRORS, SurfacelockError, UsageError
from ._types import LockResult, Report, lock_result_from_doc, report_error_text, report_from_doc

JSON_CONTRACT_VERSION = 1

def _clean(text: str, limit: int = 4096) -> str:
    """Neutralize control characters in untrusted subprocess text bound for an
    exception message. The CLI sanitizes its own stderr, but a crashed binary's
    output (or a wrong SURFACELOCK_BIN) never passed through that path."""
    out = "".join(ch if (ch.isprintable() or ch in " \n\t") else repr(ch)[1:-1] for ch in text)
    return out[:limit]


def run_verb(
    verb: str,
    args: List[str],
    *,
    binary: Optional[str],
    timeout: float,
    process_budget: Optional[float],
) -> Tuple[int, Optional[Mapping[str, Any]], str]:
    """Run one CLI verb with --json and return (exit_code, report_doc, stderr).

    report_doc is None only when the contract permits it: a flag-parse usage
    error. Anywhere else a missing/unparseable report is an error here, not a
    silent None — exit 0 with no report must never be trusted.

    timeout is the CLI's own per-server fetch budget (--timeout), enforced by
    the Go side's context per entry — every fetch phase carries its own bound.
    process_budget, when set, additionally kills the whole subprocess: a hard
    stop for callers who want one. It must cover the SUM of per-server budgets
    on a multi-entry verify, which the bindings cannot know without parsing the
    lockfile (the one canonical parser is the Go side), so it defaults to None.
    """
    timeout = _check_seconds("timeout", timeout)
    if process_budget is not None:
        process_budget = _check_seconds("process_budget", process_budget)
    # All caller strings are validated BEFORE any path lookup or subprocess:
    # a NUL would otherwise surface as a bare ValueError from pathlib or
    # subprocess, and caller misuse must arrive as the caller-misuse type.
    # binary alone may be None (meaning: discover); args may not contain None.
    if binary is not None:
        _check_arg("binary", binary)
    for a in args:
        _check_arg("argument", a)
    argv = [find_binary(binary), verb, "--json", "--timeout", _go_duration(timeout), *args]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=process_budget)
    except subprocess.TimeoutExpired as exc:
        # Deliberately NOT TransportError: no transport failure was observed —
        # the caller's own process budget ran out, and the remedy (raise the
        # budget) is the caller's, not the network's.
        raise SurfacelockError(
            f"surfacelock {verb} exceeded the caller's {process_budget:g}s process budget",
            exit_code=None,
        ) from exc
    except OSError as exc:
        raise SurfacelockError(f"could not run {argv[0]!r}: {exc}") from exc

    stderr = _clean(proc.stderr.decode("utf-8", errors="replace"))
    code = proc.returncode

    if code < 0 or code > 5:
        # Killed by a signal or a crash: not a verdict of any kind.
        raise SurfacelockError(
            f"surfacelock {verb} did not complete (exit {code}): {stderr}".rstrip(": "),
            exit_code=code,
        )

    stdout = proc.stdout.decode("utf-8", errors="replace")
    if not stdout.strip():
        # The contract's one no-report path is a flag-parse failure (exit 2) —
        # but the bindings construct the argv themselves and validate caller
        # values first, so reaching it means the BINARY does not speak these
        # flags (too old for --json, or a wrong SURFACELOCK_BIN). That is an
        # environment problem, not caller misuse: base type, not UsageError.
        raise SurfacelockError(
            f"surfacelock {verb} exited {code} without a machine report "
            f"(binary older than the --json contract, or not surfacelock?): {stderr}".rstrip(": "),
            exit_code=code,
        )

    try:
        doc = json.loads(stdout)
    except ValueError as exc:
        raise SurfacelockError(
            f"surfacelock {verb} wrote an unparseable report: {exc}", exit_code=code
        ) from exc
    if not isinstance(doc, dict):
        raise SurfacelockError(
            f"surfacelock {verb} report is not an object", exit_code=code
        )
    got = doc.get("surfacelock_json")
    # type(x) is int, not ==: bool subclasses int in Python, so true == 1 and a
    # doc saying {"surfacelock_json": true} must not pass the version gate.
    if type(got) is not int or got != JSON_CONTRACT_VERSION:
        raise SurfacelockError(
            f"surfacelock report contract version {got!r}; these bindings "
            f"implement {JSON_CONTRACT_VERSION}",
            exit_code=code,
        )
    rep_exit = doc.get("exit")
    if type(rep_exit) is not int or rep_exit != code:
        raise SurfacelockError(
            f"report exit {rep_exit!r} disagrees with process exit {code}",
            exit_code=code,
        )
    return code, doc, stderr


def raise_for(code: int, doc: Optional[Mapping[str, Any]], stderr: str,
              *, report: Optional[Report] = None) -> None:
    """Raise the typed exception for a non-zero exit. code must be 1–5.

    The message is _clean'd even though the Go side sanitizes what it emits:
    the doc's error text is exactly the field a wrong or hostile binary
    controls, and str(exc) lands in terminals and logs. Structured report
    fields stay faithful data; only display text is neutralized here.
    """
    err_cls = EXIT_ERRORS[code]
    message = _clean(report_error_text(doc) or stderr.strip() or f"surfacelock exited {code}")
    raise err_cls(message, exit_code=code, report=report)


def parse_report(doc: Mapping[str, Any], code: int) -> Report:
    """report_from_doc with malformed-document failures mapped to the protocol
    error type — a doc missing required keys must surface as a SurfacelockError,
    never a bare KeyError/TypeError from inside the bindings."""
    try:
        return report_from_doc(doc)
    except SurfacelockError:
        raise
    except Exception as exc:
        # Any decode failure, whatever built-in it surfaces as: a doc our own
        # binary never emits means a wrong binary, the protocol error type.
        raise SurfacelockError(
            f"malformed surfacelock report: {exc!r}", exit_code=code
        ) from exc


def parse_lock_result(doc: Mapping[str, Any], code: int) -> LockResult:
    """lock_result_from_doc with the same malformed-document mapping."""
    try:
        return lock_result_from_doc(doc)
    except SurfacelockError:
        raise
    except Exception as exc:
        raise SurfacelockError(
            f"malformed surfacelock report: {exc!r}", exit_code=code
        ) from exc


def _check_arg(what: str, a: Any) -> None:
    """Refuse a non-string or NUL-carrying argv element as caller misuse.

    The refusal message names only the TYPE for non-strings: repr of an
    arbitrary object can itself raise (a >4300-digit int trips CPython's
    int-to-str limit), and the guard must not fail inside its own refusal.
    """
    if not isinstance(a, str):
        raise UsageError(f"invalid {what}: expected str, got {type(a).__name__}")
    if "\x00" in a:
        raise UsageError(f"invalid {what} {a!r}")


def _check_seconds(name: str, value: Any) -> float:
    """Validate a seconds value into a float Go's duration syntax can carry.

    bool is rejected explicitly (it subclasses int, so True would silently mean
    1 s); the bounds keep _go_duration exact and exponent-free — Go's
    ParseDuration accepts neither "1e-06s" nor astronomically long durations,
    and a huge int would overflow math.isfinite before any other check ran.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UsageError(f"{name} must be a number of seconds, not {value!r}")
    try:
        f = float(value)
    except OverflowError as exc:
        # No {value!r} here: repr of a >4300-digit int raises ValueError while
        # BUILDING the message (CPython's int-to-str digit limit) — the guard
        # must not fail inside its own refusal.
        raise UsageError(f"{name} is out of range") from exc
    if not math.isfinite(f) or not (0.001 <= f <= 10**9):
        raise UsageError(f"{name} must be between 0.001 and 1e9 seconds, not {f!r}")
    return f


def _go_duration(seconds: float) -> str:
    # Fixed-point, never exponent notation: Go's ParseDuration rejects "1e-06s".
    # Bounds enforced by _check_seconds keep this exact at 9 decimal places.
    text = f"{seconds:.9f}".rstrip("0").rstrip(".")
    return f"{text}s"
