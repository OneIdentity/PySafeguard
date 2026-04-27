"""Unit tests for pysafeguard.utility — pure helper functions."""

import pytest

from pysafeguard.utility import assemble_path, assemble_url, get_access_token, get_user_token


# ---------------------------------------------------------------------------
# assemble_path
# ---------------------------------------------------------------------------


class TestAssemblePath:
    def test_single_segment(self):
        assert assemble_path("service/core") == "service/core"

    def test_multiple_segments(self):
        assert assemble_path("service/core", "v4", "Users") == "service/core/v4/Users"

    def test_strips_leading_trailing_slashes(self):
        assert assemble_path("/service/core/", "/v4/", "/Users/") == "service/core/v4/Users"

    def test_none_segments_skipped(self):
        assert assemble_path("service/core", None, "Users") == "service/core/Users"

    def test_empty_string_segments_skipped_via_filter(self):
        # Empty strings are included (only None is filtered), but produce no extra slash
        assert assemble_path("service/core", "", "Users") == "service/core//Users"

    def test_all_none(self):
        assert assemble_path(None, None) == ""

    def test_no_args(self):
        assert assemble_path() == ""


# ---------------------------------------------------------------------------
# assemble_url
# ---------------------------------------------------------------------------


class TestAssembleUrl:
    def test_basic_url(self):
        url = assemble_url("myhost.example.com", "service/core/v4/Users")
        assert url == "https://myhost.example.com/service/core/v4/Users"

    def test_with_query(self):
        url = assemble_url("host", "path", {"filter": "Name eq 'foo'"})
        assert "filter=Name+eq+%27foo%27" in url

    def test_defaults(self):
        url = assemble_url()
        assert url.startswith("https://")

    def test_custom_scheme(self):
        url = assemble_url("host", "path", scheme="http")
        assert url.startswith("http://")

    def test_fragment(self):
        url = assemble_url("host", "path", fragment="section1")
        assert url.endswith("#section1")

    def test_empty_query(self):
        url = assemble_url("host", "path", {})
        assert "?" not in url


# ---------------------------------------------------------------------------
# get_access_token
# ---------------------------------------------------------------------------


class TestGetAccessToken:
    def test_happy_path(self):
        assert get_access_token({"access_token": "abc123"}) == "abc123"

    def test_missing_field(self):
        with pytest.raises(TypeError, match="access_token"):
            get_access_token({"other": "value"})

    def test_not_a_dict(self):
        with pytest.raises(TypeError, match="access_token"):
            get_access_token("not a dict")

    def test_none_value(self):
        with pytest.raises(TypeError, match="access_token"):
            get_access_token({"access_token": None})

    def test_non_string_value(self):
        with pytest.raises(TypeError, match="access_token"):
            get_access_token({"access_token": 12345})

    def test_none_input(self):
        with pytest.raises(TypeError):
            get_access_token(None)


# ---------------------------------------------------------------------------
# get_user_token
# ---------------------------------------------------------------------------


class TestGetUserToken:
    def test_happy_path(self):
        assert get_user_token({"UserToken": "tok456"}) == "tok456"

    def test_missing_field(self):
        with pytest.raises(TypeError, match="UserToken"):
            get_user_token({"other": "value"})

    def test_not_a_dict(self):
        with pytest.raises(TypeError, match="UserToken"):
            get_user_token([1, 2, 3])

    def test_none_value(self):
        with pytest.raises(TypeError, match="UserToken"):
            get_user_token({"UserToken": None})

    def test_non_string_value(self):
        with pytest.raises(TypeError, match="UserToken"):
            get_user_token({"UserToken": 999})

    def test_none_input(self):
        with pytest.raises(TypeError):
            get_user_token(None)
