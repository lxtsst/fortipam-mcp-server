"""Response redaction and structural summarization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "preshared_key",
    "privatekey",
    "private_key",
    "secret",
    "session",
    "token",
)
_EXACT_SENSITIVE_KEYS = {"key"}
_MAX_STRING = 8_000


def redact(value: Any) -> Any:
    """Recursively redact sensitive JSON fields before an MCP result is built."""

    if isinstance(value, Mapping):
        return {
            str(key): _redact_sensitive_value(nested)
            if _is_sensitive_key(str(key))
            else redact(nested)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and len(value) > _MAX_STRING:
        return f"{value[:_MAX_STRING]}…[TRUNCATED]"
    return value


def structural_summary(value: Any) -> dict[str, object]:
    """Return response shape and collection counts without raw API values."""

    if isinstance(value, Mapping):
        keys = [
            "[REDACTED_FIELD]" if _is_sensitive_key(str(key)) else str(key)
            for key in value.keys()
        ]
        collection_counts = {
            "[REDACTED_FIELD]" if _is_sensitive_key(str(key)) else str(key): len(item)
            for key, item in value.items()
            if isinstance(item, list)
        }
        return {
            "response_kind": "object",
            "top_level_keys": sorted(keys),
            "collection_counts": collection_counts,
            "redaction_applied": True,
        }
    if isinstance(value, list):
        return {
            "response_kind": "array",
            "item_count": len(value),
            "redaction_applied": True,
        }
    if value is None:
        return {"response_kind": "empty", "redaction_applied": True}
    return {
        "response_kind": type(value).__name__,
        "redaction_applied": True,
    }


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "").replace("_", "")
    return normalized in _EXACT_SENSITIVE_KEYS or any(
        part.replace("_", "") in normalized for part in _SENSITIVE_KEY_PARTS
    )


def _redact_sensitive_value(value: Any) -> Any:
    """Preserve only empty/non-empty posture for a sensitive field."""

    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return ""
    if isinstance(value, (list, tuple, dict)) and not value:
        return type(value)()
    return "[REDACTED]"
