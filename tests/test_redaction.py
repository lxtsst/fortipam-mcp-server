from __future__ import annotations

from fortipam_mcp.redaction import redact, structural_summary


def test_redacts_sensitive_fields_recursively() -> None:
    assert redact(
        {
            "status": "ok",
            "access_token": "must-not-escape",
            "nested": {"password": "must-not-escape", "items": ["one"]},
        }
    ) == {
        "status": "ok",
        "access_token": "[REDACTED]",
        "nested": {"password": "[REDACTED]", "items": ["one"]},
    }


def test_redacts_fortianalyzer_preshared_key() -> None:
    assert redact({"preshared-key": "must-not-escape"}) == {
        "preshared-key": "[REDACTED]"
    }


def test_redaction_preserves_only_sensitive_field_presence() -> None:
    assert redact(
        {
            "key": "must-not-escape",
            "api-key": "must-not-escape",
            "password": "",
            "token": None,
        }
    ) == {
        "key": "[REDACTED]",
        "api-key": "[REDACTED]",
        "password": "",
        "token": None,
    }


def test_structural_summary_never_returns_object_values() -> None:
    summary = structural_summary(
        {
            "results": [{"name": "private-value"}],
            "secret": "must-not-escape",
        }
    )
    assert summary["response_kind"] == "object"
    assert summary["collection_counts"] == {"results": 1}
    assert "private-value" not in str(summary)
    assert "[REDACTED_FIELD]" in summary["top_level_keys"]


def test_structural_summary_redacts_sensitive_collection_names() -> None:
    summary = structural_summary({"access_tokens": ["one"], "results": []})

    assert "access_tokens" not in str(summary)
    assert summary["collection_counts"] == {
        "[REDACTED_FIELD]": 1,
        "results": 0,
    }
