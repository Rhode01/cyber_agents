"""Tests for local-target classification and the agents' local-target handling."""

from __future__ import annotations

from ai_engine.agents.common.targets import is_local_target


class TestIsLocalTarget:
    def test_loopback_hostnames(self) -> None:
        assert is_local_target("localhost")
        assert is_local_target("http://localhost:8081/login.php")
        assert is_local_target("app.localhost")

    def test_loopback_ip_literals(self) -> None:
        assert is_local_target("127.0.0.1")
        assert is_local_target("127.1.2.3")
        assert is_local_target("http://127.0.0.1:8080")
        assert is_local_target("[::1]:8000")

    def test_private_and_link_local(self) -> None:
        assert is_local_target("192.168.1.1")
        assert is_local_target("http://192.168.1.1:8080/")
        assert is_local_target("10.0.0.20")
        assert is_local_target("172.16.5.5")
        assert is_local_target("169.254.10.10")

    def test_local_suffixes(self) -> None:
        assert is_local_target("router.internal")
        assert is_local_target("printer.local")

    def test_external_targets_are_not_local(self) -> None:
        assert not is_local_target("example.com")
        assert not is_local_target("https://app.example.com/login")
        assert not is_local_target("8.8.8.8")
        assert not is_local_target("2001:4860:4860::8888")
        assert not is_local_target("")

    def test_weird_input_does_not_crash(self) -> None:
        assert not is_local_target("not a url")
        assert is_local_target("::")  # unspecified IPv6 is not an external host
