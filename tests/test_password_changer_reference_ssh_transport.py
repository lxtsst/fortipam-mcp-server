"""Behavior checks for the fixed Password Changer reference classifier."""

import pytest

from fortipam_mcp.password_changer_reference_ssh_transport import (
    PasswordChangerReferenceSshTransportError,
    classify_password_changer_references,
)


TARGET = "mcp-v4-bp013-unix-changer-r4-20260930"
SOURCE = b'set password-changer-name "SSH Password (Unix)"'


def _outputs() -> dict[str, bytes]:
    return {
        "template": b"config secret template\nedit Unix\n" + SOURCE + b"\nnext\nend\n",
        "database": b"config secret database\nend\n",
        "target": b"config secret target\nend\n",
    }


def test_reference_classifier_requires_complete_positive_control_and_zero_refs() -> None:
    baseline = _outputs()
    assert classify_password_changer_references(baseline, TARGET).verified_zero

    referenced = _outputs()
    referenced["template"] += f'set password-changer-name "{TARGET}"\n'.encode()
    assert not classify_password_changer_references(referenced, TARGET).verified_zero

    for context in ("database", "target"):
        referenced = _outputs()
        referenced[context] += TARGET.encode()
        assert not classify_password_changer_references(referenced, TARGET).verified_zero

    for broken in (
        {"template": baseline["template"], "database": baseline["database"]},
        {**baseline, "template": b"config secret template\nend\n"},
        {**baseline, "template": baseline["template"] + b"--More--"},
    ):
        with pytest.raises(PasswordChangerReferenceSshTransportError):
            classify_password_changer_references(broken, TARGET)
