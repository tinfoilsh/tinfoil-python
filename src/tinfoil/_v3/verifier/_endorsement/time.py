"""The window of approval times that a verification accepts, anchored on the caller's clock."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

DEFAULT_MAX_AGE = timedelta(days=7)
DEFAULT_FUTURE_SKEW = timedelta(minutes=5)


class TimePolicyError(ValueError):
    """A clock or window that cannot be used, or an approval time outside the window."""


@dataclass(frozen=True, slots=True)
class TimePolicy:
    """The accepted window: ``earliest`` is now minus the maximum age, ``latest`` now plus the future skew."""

    earliest: datetime
    latest: datetime

    def verify(self, at: datetime) -> None:
        """Reject an approval time before ``earliest`` ("too old") or after ``latest`` ("in the future")."""
        raise NotImplementedError


def new_time_policy(
    now: datetime, max_age: timedelta | None = None, future_skew: timedelta | None = None
) -> TimePolicy:
    """Build the window around ``now``.

    ``now`` must be timezone-aware; None selects DEFAULT_MAX_AGE or
    DEFAULT_FUTURE_SKEW; a negative age or skew is an error, and a zero one
    is honoured.
    """
    raise NotImplementedError
