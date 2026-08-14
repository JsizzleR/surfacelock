"""Typed errors mirroring the CLI's SPEC.md §9 exit-code contract.

The caller must be able to key the remedy on the exception TYPE: "the surface
changed" (DriftError — review and pin), "the server could not be reached"
(TransportError — retry/network), "the lockfile is bad" (LockfileError — restore
it), "the server served garbage" (InadmissibleSurfaceError — no verdict exists),
and "the call itself was wrong" (UsageError — fix the caller). Collapsing these
into one exception with a message would force message-parsing, which is the
failure mode the exit codes exist to prevent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ._types import Report


class SurfacelockError(Exception):
    """Base for all surfacelock errors.

    Attributes:
        exit_code: the CLI exit code, or None when the failure happened on the
            Python side (binary missing, report unparseable).
        report: the parsed machine report for the run, when one exists. On a
            multi-server run this can carry findings BESIDE the failure that
            chose the exception type — a drift found next to a transport
            failure is still in here, fully classified.
    """

    def __init__(self, message: str, *, exit_code: Optional[int] = None,
                 report: "Optional[Report]" = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.report = report


class UsageError(SurfacelockError):
    """The call was malformed (CLI exit 2), or the bindings were misused."""


class DriftError(SurfacelockError):
    """verify found drift (CLI exit 1). The classified diff is in .report."""


class TransportError(SurfacelockError):
    """No admissible surface could be fetched (CLI exit 3)."""


class LockfileError(SurfacelockError):
    """The lockfile is missing, unparseable, invalid, or self-inconsistent (CLI exit 4)."""


class InadmissibleSurfaceError(SurfacelockError):
    """The server served something no verdict can be built on (CLI exit 5)."""


# Exit-code → exception type. Keyed on the SPEC.md §9 contract, never on
# message text. Unknown codes (a crashed or signal-killed binary) fall through
# to SurfacelockError in _run.
EXIT_ERRORS = {
    1: DriftError,
    2: UsageError,
    3: TransportError,
    4: LockfileError,
    5: InadmissibleSurfaceError,
}
