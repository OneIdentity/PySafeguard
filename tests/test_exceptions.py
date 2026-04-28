"""Unit tests for pysafeguard.exceptions — SafeguardException structured parsing."""

from pysafeguard.exceptions import SafeguardException


class TestSafeguardExceptionBasic:
    def test_plain_message(self):
        ex = SafeguardException("something went wrong")
        assert str(ex) == "something went wrong"
        assert ex.status_code is None
        assert ex.error_code is None
        assert ex.error_message is None
        assert ex.response is None

    def test_inherits_exception(self):
        assert isinstance(SafeguardException(), Exception)

    def test_has_response_false_when_none(self):
        ex = SafeguardException("err")
        assert not ex.has_response

    def test_has_response_true_when_provided(self):
        ex = SafeguardException("err", response='{"Code": 1}')
        assert ex.has_response


class TestSafeguardExceptionJsonParsing:
    def test_parses_code_and_message(self):
        body = '{"Code": 60519, "Message": "Invalid STS access_token."}'
        ex = SafeguardException("err", status_code=400, response=body)
        assert ex.error_code == 60519
        assert ex.error_message == "Invalid STS access_token."
        assert ex.status_code == 400

    def test_parses_oauth_error_field(self):
        body = '{"error": "invalid_request", "error_description": "Access denied."}'
        ex = SafeguardException("err", response=body)
        assert ex.error_message == "invalid_request"

    def test_code_field_takes_precedence_over_error(self):
        body = '{"Code": 1, "Message": "primary", "error": "secondary"}'
        ex = SafeguardException("err", response=body)
        assert ex.error_message == "primary"

    def test_non_json_response_no_crash(self):
        ex = SafeguardException("err", response="<html>not json</html>")
        assert ex.error_code is None
        assert ex.error_message is None
        assert ex.response == "<html>not json</html>"

    def test_empty_json_object(self):
        ex = SafeguardException("err", response="{}")
        assert ex.error_code is None
        assert ex.error_message is None

    def test_json_array_response(self):
        ex = SafeguardException("err", response="[1, 2, 3]")
        assert ex.error_code is None

    def test_display_falls_back_to_error_message(self):
        """When message arg is empty, display uses parsed error_message."""
        body = '{"Code": 1, "Message": "Token expired."}'
        ex = SafeguardException("", response=body)
        assert str(ex) == "Token expired."

    def test_display_prefers_explicit_message(self):
        body = '{"Code": 1, "Message": "Token expired."}'
        ex = SafeguardException("custom error", response=body)
        assert str(ex) == "custom error"
