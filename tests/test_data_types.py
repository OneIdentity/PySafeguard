# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Unit tests for pysafeguard.data_types — enum definitions and StrEnum behavior."""

from pysafeguard.data_types import A2AType, A2ATypes, HttpMethod, HttpMethods, Service, Services, SshKeyFormat, SshKeyFormats


class TestService:
    def test_core(self):
        assert Service.CORE == "service/core"

    def test_appliance(self):
        assert Service.APPLIANCE == "service/appliance"

    def test_notification(self):
        assert Service.NOTIFICATION == "service/notification"

    def test_a2a(self):
        assert Service.A2A == "service/a2a"

    def test_event(self):
        assert Service.EVENT == "service/event"

    def test_rsts(self):
        assert Service.RSTS == "RSTS"

    def test_is_str(self):
        assert isinstance(Service.CORE, str)

    def test_string_concatenation(self):
        assert "https://host/" + Service.CORE == "https://host/service/core"


class TestHttpMethod:
    def test_values(self):
        assert HttpMethod.GET == "GET"
        assert HttpMethod.POST == "POST"
        assert HttpMethod.PUT == "PUT"
        assert HttpMethod.DELETE == "DELETE"

    def test_is_str(self):
        assert isinstance(HttpMethod.GET, str)


class TestA2AType:
    def test_values(self):
        assert A2AType.PASSWORD == "password"
        assert A2AType.PRIVATEKEY == "privatekey"
        assert A2AType.APIKEYSECRET == "apikey"


class TestSshKeyFormat:
    def test_values(self):
        assert SshKeyFormat.OPENSSH == "openssh"
        assert SshKeyFormat.SSH2 == "ssh2"
        assert SshKeyFormat.PUTTY == "putty"


class TestLegacyAliases:
    """Verify deprecated plural aliases still resolve to the same enum."""

    def test_services_alias(self):
        assert Services is Service

    def test_http_methods_alias(self):
        assert HttpMethods is HttpMethod

    def test_a2a_types_alias(self):
        assert A2ATypes is A2AType

    def test_ssh_key_formats_alias(self):
        assert SshKeyFormats is SshKeyFormat
