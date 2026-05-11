from pathlib import Path

import pytest

from periscope.policy import (
    Policy,
    PolicyError,
    load_policy,
    match_endpoint,
    match_host,
)


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "policy.toml"
    p.write_text(content)
    return p


# ===== load_policy =====


def test_load_policy_minimal_file(tmp_path: Path) -> None:
    p = _write(tmp_path, "")
    policy = load_policy(p)
    assert policy == Policy()


def test_load_policy_full_file(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        """
        [dns]
        allowed = ["example.com", "*.cdn.com"]

        [sni]
        allowed = ["example.com"]

        [tcp]
        allowed = ["1.2.3.4:443", "8.8.8.8:*"]

        [udp]
        allowed = ["8.8.8.8:53"]

        [quic]
        allowed = ["1.1.1.1:443"]
        """,
    )
    policy = load_policy(p)
    assert policy.dns == frozenset({"example.com", "*.cdn.com"})
    assert policy.sni == frozenset({"example.com"})
    assert policy.tcp == frozenset({("1.2.3.4", 443), ("8.8.8.8", None)})
    assert policy.udp == frozenset({("8.8.8.8", 53)})
    assert policy.quic == frozenset({("1.1.1.1", 443)})


def test_load_policy_missing_section_yields_empty_frozenset(tmp_path: Path) -> None:
    p = _write(tmp_path, '[dns]\nallowed = ["example.com"]\n')
    policy = load_policy(p)
    assert policy.dns == frozenset({"example.com"})
    assert policy.sni == frozenset()
    assert policy.tcp == frozenset()


def test_load_policy_rejects_unknown_section(tmp_path: Path) -> None:
    p = _write(tmp_path, "[http]\nallowed = []\n")
    with pytest.raises(PolicyError, match="unknown section"):
        load_policy(p)


def test_load_policy_rejects_unknown_key_in_section(tmp_path: Path) -> None:
    p = _write(tmp_path, '[dns]\nallowed = ["a.com"]\nblocked = ["b.com"]\n')
    with pytest.raises(PolicyError, match="unknown key"):
        load_policy(p)


def test_load_policy_rejects_allowed_not_a_list(tmp_path: Path) -> None:
    p = _write(tmp_path, '[dns]\nallowed = "example.com"\n')
    with pytest.raises(PolicyError, match="list of strings"):
        load_policy(p)


def test_load_policy_rejects_endpoint_missing_colon(tmp_path: Path) -> None:
    p = _write(tmp_path, '[tcp]\nallowed = ["1.2.3.4"]\n')
    with pytest.raises(PolicyError, match="ip:port"):
        load_policy(p)


def test_load_policy_rejects_non_integer_port(tmp_path: Path) -> None:
    p = _write(tmp_path, '[tcp]\nallowed = ["1.2.3.4:http"]\n')
    with pytest.raises(PolicyError, match="port must be integer"):
        load_policy(p)


def test_load_policy_rejects_port_out_of_range(tmp_path: Path) -> None:
    p = _write(tmp_path, '[tcp]\nallowed = ["1.2.3.4:99999"]\n')
    with pytest.raises(PolicyError, match="out of range"):
        load_policy(p)


def test_load_policy_rejects_malformed_toml(tmp_path: Path) -> None:
    p = _write(tmp_path, "[dns\nallowed = []\n")
    with pytest.raises(PolicyError, match="invalid TOML"):
        load_policy(p)


def test_load_policy_section_must_be_table(tmp_path: Path) -> None:
    p = _write(tmp_path, 'dns = ["example.com"]\n')
    with pytest.raises(PolicyError, match="must be a table"):
        load_policy(p)


# ===== match_host =====


def test_match_host_exact() -> None:
    assert match_host("example.com", ["example.com"]) == "example.com"


def test_match_host_no_match() -> None:
    assert match_host("foo.com", ["example.com"]) is None


def test_match_host_wildcard_matches_subdomain() -> None:
    assert match_host("foo.example.com", ["*.example.com"]) == "*.example.com"


def test_match_host_wildcard_matches_deep_subdomain() -> None:
    assert match_host("a.b.example.com", ["*.example.com"]) == "*.example.com"


def test_match_host_wildcard_does_not_match_apex() -> None:
    assert match_host("example.com", ["*.example.com"]) is None


def test_match_host_strips_trailing_dot() -> None:
    assert match_host("example.com.", ["example.com"]) == "example.com"


# ===== match_endpoint =====


def test_match_endpoint_exact() -> None:
    assert match_endpoint("1.2.3.4", 443, [("1.2.3.4", 443)]) == ("1.2.3.4", 443)


def test_match_endpoint_port_mismatch() -> None:
    assert match_endpoint("1.2.3.4", 80, [("1.2.3.4", 443)]) is None


def test_match_endpoint_port_wildcard() -> None:
    assert match_endpoint("1.2.3.4", 8080, [("1.2.3.4", None)]) == ("1.2.3.4", None)


def test_match_endpoint_ip_mismatch() -> None:
    assert match_endpoint("9.9.9.9", 443, [("1.2.3.4", None)]) is None
