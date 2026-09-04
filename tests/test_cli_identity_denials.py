from __future__ import annotations

import pytest

from scripts.accept_cli_identity_denials import (
    _PROBES,
    classify_probe_output,
    summarize_probe_classifications,
)


def test_cli_denial_probe_registry_is_fixed_and_non_mutating() -> None:
    assert tuple((probe.probe_id, probe.command) for probe in _PROBES) == (
        ("required_admin_configuration_context", b"config system admin"),
        ("debug_branch", b"diagnose debug status"),
        ("execute_branch", b"execute ping-options view-settings"),
        ("secret_branch", b"show secret jwt"),
    )
    assert all(b" set " not in b" " + probe.command + b" " for probe in _PROBES)
    assert _PROBES[0].accepted_classifications == {
        "denied",
        "allowed_context_change",
    }
    assert all(
        probe.accepted_classifications == {"denied", "invalid_or_rejected"}
        for probe in _PROBES[1:]
    )


def test_cli_denial_classifier_accepts_explicit_permission_evidence_only() -> None:
    prompt = b"fpa #"
    assert classify_probe_output(
        b"You are not entitled to run the command.\r\nCommand fail. Return code -37\r\nfpa #",
        initial_prompt=prompt,
        final_prompt=prompt,
    ) == "denied"
    assert classify_probe_output(
        b"No permission for this admin to read any data\r\nfpa #",
        initial_prompt=prompt,
        final_prompt=prompt,
    ) == "denied"


def test_cli_denial_classifier_rejects_invalid_or_allowed_results() -> None:
    prompt = b"fpa #"
    assert classify_probe_output(
        b"Command fail. Return code -61\r\nfpa #",
        initial_prompt=prompt,
        final_prompt=prompt,
    ) == "invalid_or_rejected"
    assert classify_probe_output(
        b"Ping Options:\r\nfpa #",
        initial_prompt=prompt,
        final_prompt=prompt,
    ) == "allowed_or_inconclusive"
    assert classify_probe_output(
        b"fpa (global) #",
        initial_prompt=prompt,
        final_prompt=b"fpa (global) #",
    ) == "allowed_context_change"


@pytest.mark.parametrize(
    "configuration_classification,reachable",
    (("denied", False), ("allowed_context_change", True)),
)
def test_authorization_summary_accepts_both_conclusive_admin_context_results(
    configuration_classification: str,
    reachable: bool,
) -> None:
    result = summarize_probe_classifications(
        {
            "required_admin_configuration_context": configuration_classification,
            "debug_branch": "denied",
            "execute_branch": "denied",
            "secret_branch": "denied",
        }
    )
    assert result["identity_authorization_boundary_accepted"] is True
    assert result["required_admin_context_reachable"] is reachable
    assert result["persistent_write_attempted"] is False


def test_authorization_summary_accepts_command_tree_rejection_for_prohibited_branches() -> None:
    result = summarize_probe_classifications(
        {
            "required_admin_configuration_context": "allowed_context_change",
            "debug_branch": "invalid_or_rejected",
            "execute_branch": "invalid_or_rejected",
            "secret_branch": "invalid_or_rejected",
        }
    )
    assert result["identity_authorization_boundary_accepted"] is True
    assert result["command_tree_rejection_count"] == 3
    assert result["non_executable_prohibited_probe_count"] == 3


def test_authorization_summary_rejects_inconclusive_or_incomplete_results() -> None:
    result = summarize_probe_classifications(
        {
            "required_admin_configuration_context": "allowed_context_change",
            "debug_branch": "allowed_or_inconclusive",
            "execute_branch": "denied",
            "secret_branch": "denied",
        }
    )
    assert result["identity_authorization_boundary_accepted"] is False
    assert result["failed_probe_ids"] == ["debug_branch"]
    with pytest.raises(ValueError, match="incomplete"):
        summarize_probe_classifications({"debug_branch": "denied"})
