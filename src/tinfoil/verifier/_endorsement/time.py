"""The window of approval times that a verification accepts, anchored on the caller's clock."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

DEFAULT_MAX_AGE = timedelta(days=7)
DEFAULT_FUTURE_SKEW = timedelta(minutes=5)
MAX_AGE_SPAN = datetime.max - datetime.min
"""The longest age that any window can hold: the span between the earliest and the latest representable instants.
A longer age overflows ``now - max_age`` for every ``now``; a shorter one can still overflow for a ``now`` near the
earliest instant, which the window builder reports."""


class TimePolicyError(ValueError):
    """A clock or window that cannot be used, or an approval time outside the window."""


@dataclass(frozen=True, slots=True)
class TimePolicy:
    """The accepted window: ``earliest`` is now minus the maximum age, ``latest`` now plus the future skew."""

    earliest: datetime
    latest: datetime

    def verify(self, at: datetime) -> None:
        """Reject an approval time before ``earliest`` ("too old") or after ``latest`` ("in the future")."""
        require_aware(at)
        if at < self.earliest:
            raise TimePolicyError("approval is too old")
        if at > self.latest:
            raise TimePolicyError("timestamp is in the future")


def new_time_policy(
    now: datetime, max_age: timedelta | None = None, future_skew: timedelta | None = None
) -> TimePolicy:
    """Build the window around ``now``.

    ``now`` must be timezone-aware; None selects DEFAULT_MAX_AGE or
    DEFAULT_FUTURE_SKEW; a negative age or skew is an error, and a zero one
    is honored. An age or skew that puts either edge of the window outside
    the representable date range is an error.
    """
    if max_age is None:
        max_age = DEFAULT_MAX_AGE
    if future_skew is None:
        future_skew = DEFAULT_FUTURE_SKEW
    if not isinstance(now, datetime) or not _is_aware(now) or max_age < timedelta(0) or future_skew < timedelta(0):
        raise TimePolicyError("clock and nonnegative age and skew are required")
    try:
        return TimePolicy(earliest=now - max_age, latest=now + future_skew)
    except OverflowError as err:
        raise TimePolicyError("window is outside the representable date range") from err


def require_aware(at: datetime) -> None:
    """Reject a naive datetime: every time that the verifier compares carries a zone."""
    if not _is_aware(at):
        raise TimePolicyError("time must be timezone-aware")


def _is_aware(at: datetime) -> bool:
    return at.tzinfo is not None and at.utcoffset() is not None
