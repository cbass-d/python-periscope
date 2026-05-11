"""Declarative egress policy: per-channel allowlists loaded from TOML."""

import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

_HOST_CHANNELS = ("dns", "sni")
_ENDPOINT_CHANNELS = ("tcp", "udp", "quic")
_KNOWN_CHANNELS = _HOST_CHANNELS + _ENDPOINT_CHANNELS


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass(frozen=True)
class Policy:
    """Allowed entries per capture channel. Empty frozenset = no allowlist."""

    dns: frozenset[str] = field(default_factory=frozenset)
    sni: frozenset[str] = field(default_factory=frozenset)
    tcp: frozenset[tuple[str, int | None]] = field(default_factory=frozenset)
    udp: frozenset[tuple[str, int | None]] = field(default_factory=frozenset)
    quic: frozenset[tuple[str, int | None]] = field(default_factory=frozenset)


def load_policy(path: Path) -> Policy:
    """Parse a TOML policy file. Raises PolicyError on malformed input."""
    try:
        raw = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{path}: invalid TOML: {e}") from e
    except OSError as e:
        raise PolicyError(f"{path}: cannot read: {e}") from e

    unknown = set(raw) - set(_KNOWN_CHANNELS)
    if unknown:
        raise PolicyError(
            f"{path}: unknown section(s): {', '.join(sorted(unknown))}. "
            f"Valid sections: {', '.join(_KNOWN_CHANNELS)}"
        )

    kwargs: dict[str, frozenset[str] | frozenset[tuple[str, int | None]]] = {}
    for channel in _HOST_CHANNELS:
        entries = _section_allowed(raw, path, channel)
        kwargs[channel] = frozenset(entries)
    for channel in _ENDPOINT_CHANNELS:
        entries = _section_allowed(raw, path, channel)
        kwargs[channel] = frozenset(_parse_endpoint(e, path, channel) for e in entries)

    return Policy(**kwargs)  # type: ignore[arg-type]


def _section_allowed(raw: dict[str, object], path: Path, channel: str) -> list[str]:
    section = raw.get(channel)
    if section is None:
        return []
    if not isinstance(section, dict):
        raise PolicyError(f"{path}: [{channel}] must be a table")
    extra = set(section) - {"allowed"}
    if extra:
        raise PolicyError(f"{path}: [{channel}] has unknown key(s): {', '.join(sorted(extra))}")
    allowed = section.get("allowed", [])
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise PolicyError(f"{path}: [{channel}].allowed must be a list of strings")
    return allowed


def _parse_endpoint(spec: str, path: Path, channel: str) -> tuple[str, int | None]:
    if ":" not in spec:
        raise PolicyError(f"{path}: [{channel}].allowed entry {spec!r} must be 'ip:port' or 'ip:*'")
    ip, _, port_str = spec.rpartition(":")
    if not ip:
        raise PolicyError(f"{path}: [{channel}].allowed entry {spec!r} missing ip")
    if port_str == "*":
        return (ip, None)
    try:
        port = int(port_str)
    except ValueError as e:
        raise PolicyError(
            f"{path}: [{channel}].allowed entry {spec!r}: port must be integer or '*'"
        ) from e
    if not 0 <= port <= 65535:
        raise PolicyError(f"{path}: [{channel}].allowed entry {spec!r}: port out of range")
    return (ip, port)


def match_host(name: str, patterns: Iterable[str]) -> str | None:
    """Return the matching pattern, or None. Supports `*.suffix` wildcards."""
    name = name.rstrip(".")
    for pat in patterns:
        if pat.startswith("*."):
            suffix = pat[2:]
            if name.endswith("." + suffix):
                return pat
        elif name == pat:
            return pat
    return None


def match_endpoint(
    ip: str, port: int, patterns: Iterable[tuple[str, int | None]]
) -> tuple[str, int | None] | None:
    """Return the matching pattern, or None. Port `None` in pattern = wildcard."""
    for pat in patterns:
        pat_ip, pat_port = pat
        if pat_ip == ip and (pat_port is None or pat_port == port):
            return pat
    return None
