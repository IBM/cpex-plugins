"""Tests for _parse_rate helper."""

import pytest

from cpex_rate_limiter.rate_limiter import _parse_rate


class TestParseRate:
    """Validate rate-string parsing into (count, window_seconds)."""

    @pytest.mark.parametrize(
        "rate, expected",
        [
            ("60/s", (60, 1)),
            ("60/sec", (60, 1)),
            ("60/second", (60, 1)),
            ("10/m", (10, 60)),
            ("10/min", (10, 60)),
            ("10/minute", (10, 60)),
            ("100/h", (100, 3600)),
            ("100/hr", (100, 3600)),
            ("100/hour", (100, 3600)),
        ],
    )
    def test_valid_rates(self, rate, expected):
        assert _parse_rate(rate) == expected

    @pytest.mark.parametrize(
        "rate, expected",
        [
            ("60/ S ", (60, 1)),
            ("10/ MIN", (10, 60)),
        ],
    )
    def test_unit_whitespace_and_case(self, rate, expected):
        assert _parse_rate(rate) == expected

    @pytest.mark.parametrize(
        "rate",
        [
            "abc/m",
            "/m",
            "60",
            "",
            "60/x",
            "60/days",
            "0/m",
            "-1/s",
        ],
    )
    def test_invalid_rates(self, rate):
        with pytest.raises(ValueError):
            _parse_rate(rate)

    def test_none_raises(self):
        with pytest.raises((ValueError, AttributeError)):
            _parse_rate(None)
