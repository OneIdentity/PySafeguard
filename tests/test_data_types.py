"""Unit tests for pysafeguard.data_types — enum definitions and StrEnum behavior."""

from pysafeguard.data_types import A2ATypes, HttpMethods, Services, SshKeyFormats


class TestServices:
    def test_core(self):
        assert Services.CORE == "service/core"

    def test_appliance(self):
        assert Services.APPLIANCE == "service/appliance"

    def test_notification(self):
        assert Services.NOTIFICATION == "service/notification"

    def test_a2a(self):
        assert Services.A2A == "service/a2a"

    def test_event(self):
        assert Services.EVENT == "service/event"

    def test_rsts(self):
        assert Services.RSTS == "RSTS"

    def test_is_str(self):
        assert isinstance(Services.CORE, str)

    def test_string_concatenation(self):
        # StrEnum values should work seamlessly in string operations
        assert "https://host/" + Services.CORE == "https://host/service/core"


class TestHttpMethods:
    def test_values(self):
        assert HttpMethods.GET == "GET"
        assert HttpMethods.POST == "POST"
        assert HttpMethods.PUT == "PUT"
        assert HttpMethods.DELETE == "DELETE"

    def test_is_str(self):
        assert isinstance(HttpMethods.GET, str)


class TestA2ATypes:
    def test_values(self):
        assert A2ATypes.PASSWORD == "password"
        assert A2ATypes.PRIVATEKEY == "privatekey"
        assert A2ATypes.APIKEYSECRET == "apikey"


class TestSshKeyFormats:
    def test_values(self):
        assert SshKeyFormats.OPENSSH == "openssh"
        assert SshKeyFormats.SSH2 == "ssh2"
        assert SshKeyFormats.PUTTY == "putty"
