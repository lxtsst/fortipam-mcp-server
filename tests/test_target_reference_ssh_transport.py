from __future__ import annotations

import pytest

from fortipam_mcp.target_reference_ssh_transport import (
    TargetReferenceSshTransportError,
    _TERMINAL_COLUMNS,
    _strict_reference_count,
    _target_name,
)


COMMAND = "diagnose sys cmdb refcnt show secret.target.name mcp-v4-target-b104"
PROMPT = b"FPA-VM #"


def test_reference_name_guard_matches_the_fixed_windows_creation_profile() -> None:
    for name in ("mcp-v4-target-original", "MCPV4WinTarget20261022R1", "MCPV4WinTarget20261022R999"):
        assert _target_name(name) == name
    for name in (
        "MCPV4WinTarget20261022R0", "MCPV4WinTarget20261022R1000",
        "MCPV4WinTarget20261022R01", "MCPV4WinTarget20261022R1\n",
        "MCPV4WinTarget20261022R1;end", "mcpv4wintarget20261022r1", "shared-target",
    ):
        with pytest.raises(TargetReferenceSshTransportError):
            _target_name(name)


def test_terminal_width_preserves_the_longest_allowed_command_echo() -> None:
    max_name = "mcp-v4-target-" + "a" * 50
    command = "diagnose sys cmdb refcnt show secret.target.name " + max_name
    assert _TERMINAL_COLUMNS > len(command)


def test_strict_reference_count_accepts_only_echoed_fixed_reference_lines() -> None:
    assert _strict_reference_count(
        COMMAND.encode("ascii") + b"\n" + PROMPT,
        COMMAND,
        PROMPT,
    ) == 0
    assert _strict_reference_count(
        COMMAND.encode("ascii")
        + b"\nentry used by secret.database:name\n"
        + PROMPT,
        COMMAND,
        PROMPT,
    ) == 1


@pytest.mark.parametrize(
    "output",
    [
        b"wrong command\nFPA-VM #",
        COMMAND.encode("ascii") + b"\nunexpected output\nFPA-VM #",
        COMMAND.encode("ascii") + b"\nother-host #",
    ],
)
def test_strict_reference_count_rejects_ambiguous_output(output: bytes) -> None:
    with pytest.raises(TargetReferenceSshTransportError):
        _strict_reference_count(output, COMMAND, PROMPT)
