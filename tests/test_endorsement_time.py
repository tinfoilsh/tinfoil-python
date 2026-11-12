"""The approval time window: defaults, bounds and the inclusive edges."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tinfoil.verifier._endorsement.time import (
    DEFAULT_FUTURE_SKEW,
    DEFAULT_MAX_AGE,
    TimePolicy,
    TimePolicyError,
    new_time_policy,
)

NOW = datetime(2026, 8, 6, tzinfo=UTC)


def test_defaults_are_seven_days_and_five_minutes() -> None:
    policy = new_time_policy(NOW)
    assert policy == TimePolicy(earliest=NOW - DEFAULT_MAX_AGE, latest=NOW + DEFAULT_FUTURE_SKEW)
    assert timedelta(days=7) == DEFAULT_MAX_AGE
    assert timedelta(minutes=5) == DEFAULT_FUTURE_SKEW


def test_explicit_window_including_zero_is_honored() -> None:
    assert new_time_policy(NOW, timedelta(hours=1), timedelta(0)) == TimePolicy(NOW - timedelta(hours=1), NOW)
    assert new_time_policy(NOW, timedelta(0), timedelta(seconds=1)) == TimePolicy(NOW, NOW + timedelta(seconds=1))


@pytest.mark.parametrize(
    ("now", "max_age", "future_skew"),
    [
        (NOW.replace(tzinfo=None), None, None),
        (NOW, -timedelta(seconds=1), None),
        (NOW, None, -timedelta(seconds=1)),
    ],
)
def test_clock_and_nonnegative_window_are_required(
    now: datetime, max_age: timedelta | None, future_skew: timedelta | None
) -> None:
    with pytest.raises(TimePolicyError, match="clock and nonnegative age and skew are required"):
        new_time_policy(now, max_age, future_skew)


@pytest.mark.parametrize(
    ("max_age", "future_skew"),
    [
        (timedelta.max, None),
        (None, timedelta.max),
        (NOW - datetime.min.replace(tzinfo=UTC) + timedelta(days=1), None),
        (None, datetime.max.replace(tzinfo=UTC) - NOW + timedelta(days=1)),
    ],
)
def test_window_outside_the_date_range_is_an_error(max_age: timedelta | None, future_skew: timedelta | None) -> None:
    with pytest.raises(TimePolicyError, match="window is outside the representable date range"):
        new_time_policy(NOW, max_age, future_skew)


def test_window_at_the_date_range_edges_is_honored() -> None:
    earliest = datetime.min.replace(tzinfo=UTC)
    latest = datetime.max.replace(tzinfo=UTC)
    assert new_time_policy(NOW, NOW - earliest, latest - NOW) == TimePolicy(earliest, latest)


def test_verify_is_inclusive_at_both_edges() -> None:
    policy = new_time_policy(NOW)
    policy.verify(policy.earliest)
    policy.verify(policy.latest)
    policy.verify(NOW)
    with pytest.raises(TimePolicyError, match="approval is too old"):
        policy.verify(policy.earliest - timedelta(microseconds=1))
    with pytest.raises(TimePolicyError, match="timestamp is in the future"):
        policy.verify(policy.latest + timedelta(microseconds=1))
    with pytest.raises(TimePolicyError, match="timezone-aware"):
        policy.verify(NOW.replace(tzinfo=None))
