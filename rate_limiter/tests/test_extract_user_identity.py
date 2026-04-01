"""Tests for _extract_user_identity helper."""

import pytest

from cpex_rate_limiter.rate_limiter import _extract_user_identity


class TestExtractUserIdentity:
    """Validate normalisation of user identity values."""

    def test_dict_with_email(self):
        assert _extract_user_identity({"email": "a@b.com", "id": "123"}) == "a@b.com"

    def test_dict_fallback_to_id(self):
        assert _extract_user_identity({"id": "user-42"}) == "user-42"

    def test_dict_fallback_to_sub(self):
        assert _extract_user_identity({"sub": "sub-99"}) == "sub-99"

    def test_dict_empty_values(self):
        assert _extract_user_identity({"email": "", "id": "", "sub": ""}) == "anonymous"

    def test_dict_no_keys(self):
        assert _extract_user_identity({}) == "anonymous"

    def test_string_identity(self):
        assert _extract_user_identity("alice") == "alice"

    def test_string_strips_whitespace(self):
        assert _extract_user_identity("  bob  ") == "bob"

    def test_empty_string(self):
        assert _extract_user_identity("") == "anonymous"

    def test_whitespace_only_string(self):
        assert _extract_user_identity("   ") == "anonymous"

    def test_none(self):
        assert _extract_user_identity(None) == "anonymous"

    def test_integer_coerced(self):
        assert _extract_user_identity(42) == "42"
