from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.v4_profile_cli_batch_acceptance import (
    ProfileBatchAcceptanceError,
    _execute_batch,
    _execute_one,
)


class _Transport:
    def __init__(self, *, initially_exists: bool = False, readback_verified: bool = True) -> None:
        self.initially_exists = initially_exists
        self.readback_verified = readback_verified
        self.inspect_calls = 0
        self.create_calls: list[str] = []

    def inspect(self, profile_name: str) -> SimpleNamespace:
        self.inspect_calls += 1
        return SimpleNamespace(profile_name_exists=self.initially_exists)

    def create_and_readback(self, profile_name: str) -> SimpleNamespace:
        self.create_calls.append(profile_name)
        return SimpleNamespace(verified=self.readback_verified)


def _transports(**overrides: _Transport) -> dict[str, _Transport]:
    return {
        "antivirus_profile": overrides.get("antivirus_profile", _Transport()),
        "rdp_event_filter": overrides.get("rdp_event_filter", _Transport()),
        "ssh_filter": overrides.get("ssh_filter", _Transport()),
    }


def test_batch_rechecks_all_absent_then_creates_each_once() -> None:
    transports = _transports()

    result = _execute_batch(transports)

    assert result["preflight_absent"] is True
    assert result["antivirus_profile_verified"] is True
    assert result["rdp_event_filter_verified"] is True
    assert result["ssh_filter_verified"] is True
    assert all(transport.inspect_calls == 2 for transport in transports.values())
    assert all(len(transport.create_calls) == 1 for transport in transports.values())


def test_existing_profile_stops_before_any_write() -> None:
    existing = _Transport(initially_exists=True)
    transports = _transports(rdp_event_filter=existing)

    with pytest.raises(ProfileBatchAcceptanceError, match="current state"):
        _execute_batch(transports)

    assert all(not transport.create_calls for transport in transports.values())


def test_readback_failure_stops_remaining_profiles() -> None:
    failed = _Transport(readback_verified=False)
    transports = _transports(antivirus_profile=failed)

    with pytest.raises(ProfileBatchAcceptanceError, match="readback"):
        _execute_batch(transports)

    assert not transports["rdp_event_filter"].create_calls
    assert not transports["ssh_filter"].create_calls


def test_one_confirmed_ssh_filter_action_ignores_other_completed_profiles() -> None:
    transports = _transports(
        antivirus_profile=_Transport(initially_exists=True),
        rdp_event_filter=_Transport(initially_exists=True),
    )

    result = _execute_one(transports, "ssh_filter")

    assert result["action_kind"] == "ssh_filter"
    assert result["readback_verified"] is True
    assert not transports["antivirus_profile"].create_calls
    assert not transports["rdp_event_filter"].create_calls
    assert len(transports["ssh_filter"].create_calls) == 1
