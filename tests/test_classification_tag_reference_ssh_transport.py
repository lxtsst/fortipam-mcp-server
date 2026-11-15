from __future__ import annotations

import pytest

from fortipam_mcp.classification_tag_reference_ssh_transport import (
    ClassificationTagReferenceSshTransportError,
    _TERMINAL_COLUMNS,
    _strict_reference_count,
)


COMMAND = (
    "diagnose sys cmdb refcnt show secret.classification-tag.name "
    "mcp-v4-classification-tag-b29"
)
PROMPT = b"FPA-VM #"


def test_terminal_width_preserves_the_longest_allowed_command_echo() -> None:
    max_name = "mcp-v4-classification-tag-" + "a" * 40
    command = (
        "diagnose sys cmdb refcnt show secret.classification-tag.name " + max_name
    )
    assert _TERMINAL_COLUMNS > len(command)


def test_strict_reference_count_accepts_only_echoed_fixed_reference_lines() -> None:
    assert _strict_reference_count(
        COMMAND.encode("ascii") + b"\n" + PROMPT,
        COMMAND,
        PROMPT,
    ) == 0
    assert _strict_reference_count(
        COMMAND.encode("ascii")
        + b"\nentry used by secret.target:name\n"
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
    with pytest.raises(ClassificationTagReferenceSshTransportError):
        _strict_reference_count(output, COMMAND, PROMPT)
