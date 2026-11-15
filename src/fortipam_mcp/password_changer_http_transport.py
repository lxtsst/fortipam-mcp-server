"""Fixed FortiPAM 7.0 Unix Password Changer clone transport.

The built-in procedure stays inside this process. Callers receive only a
digest and categorical state; a workflow must reserve a durable one-shot claim
before invoking ``create_and_readback``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any
from urllib.parse import quote

from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
)


COLLECTION_PATH = "/api/v2/cmdb/secret/password-changer"
SOURCE_NAME = "SSH Password (Unix)"
DESCRIPTION = "Isolated BP013 Unix changer laboratory fixture; unreferenced"
_NAME = re.compile(r"mcp-v4-bp013-unix-changer-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_TOP_FIELDS = (
    "type", "change-auth-mode", "verify-auth-mode", "new-line-mode",
)
_STAGES = ("change", "verify", "web-change", "web-verify")
_STEP_FIELDS = frozenset({
    "seq-num", "next-seq-num", "goto-step", "type", "command", "delay",
    "description", "expect-action", "execute-action", "critical-step", "interpret",
})
_UNAVAILABLE = "FortiPAM V4 Unix Password Changer action is unavailable."


class PasswordChangerHttpTransportError(RuntimeError):
    """Non-disclosing transport or contract failure."""


@dataclass(frozen=True, slots=True)
class PasswordChangerInspection:
    source_digest: str
    target_exists: bool


@dataclass(frozen=True, slots=True)
class PasswordChangerReadback:
    post_accepted: bool
    detail_matched: bool
    collection_unique: bool
    reference_count_known_zero: bool

    @property
    def verified(self) -> bool:
        """The API clone matched; zero references needs separate UI evidence if omitted."""

        return self.post_accepted and self.detail_matched and self.collection_unique


class FortiPamUnixPasswordChangerHttpTransport:
    """Clone only the unchanged built-in Unix procedure to one bound name."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, target_name: str,
        *, client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(target_name, str) or _NAME.fullmatch(target_name) is None:
            raise PasswordChangerHttpTransportError(_UNAVAILABLE)
        self._target_name = target_name
        self._client = FortiPamSecretMetadataHttpTransport(
            config, client_factory=client_factory,
        )

    def inspect(self) -> PasswordChangerInspection:
        try:
            if self._client.read_product_version_and_build() != ("7.0.0", 29):
                raise ValueError
            rows = self._collection()
            sources = [row for row in rows if row.get("name") == SOURCE_NAME]
            targets = [row for row in rows if row.get("name") == self._target_name]
            if len(sources) != 1 or len(targets) > 1:
                raise ValueError
            body = _clone_body(sources[0], self._target_name)
            return PasswordChangerInspection(_digest(body), bool(targets))
        except Exception:
            raise PasswordChangerHttpTransportError(_UNAVAILABLE) from None

    def create_and_readback(
        self, expected: PasswordChangerInspection,
    ) -> PasswordChangerReadback:
        """Recheck the source and absence, then send at most one POST."""

        try:
            if not isinstance(expected, PasswordChangerInspection) or expected.target_exists:
                raise ValueError
            current = self.inspect()
            if current.target_exists or not hmac.compare_digest(
                current.source_digest, expected.source_digest,
            ):
                raise ValueError
            rows = self._collection()
            sources = [row for row in rows if row.get("name") == SOURCE_NAME]
            if len(sources) != 1 or any(
                row.get("name") == self._target_name for row in rows
            ):
                raise ValueError
            body = _clone_body(sources[0], self._target_name)
            if not hmac.compare_digest(_digest(body), expected.source_digest):
                raise ValueError
            status, payload = self._client._request(
                "POST", COLLECTION_PATH, body, query="vdom=root",
            )
            accepted = status == 200 and isinstance(payload, Mapping) and payload.get(
                "http_status"
            ) in (None, 200)
            detail_status, detail_payload = self._client._request(
                "GET", f"{COLLECTION_PATH}/{quote(self._target_name, safe='')}",
                None, query="vdom=root",
            )
            detail = _single_record(detail_payload) if detail_status == 200 else None
            rows_after = self._collection()
            matches = [row for row in rows_after if row.get("name") == self._target_name]
            detail_matches = detail is not None and _matches(body, detail)
            collection_unique = len(matches) == 1 and _matches(body, matches[0])
            # FortiPAM 7.0 omits q_ref from API responses. Do not infer zero.
            reference_zero = bool(
                detail is not None and detail.get("q_ref") in (0, "0")
                or len(matches) == 1 and matches[0].get("q_ref") in (0, "0")
            )
            return PasswordChangerReadback(
                accepted, detail_matches, collection_unique, reference_zero,
            )
        except Exception:
            raise PasswordChangerHttpTransportError(_UNAVAILABLE) from None

    def _collection(self) -> list[Mapping[str, object]]:
        status, payload = self._client._request(
            "GET", COLLECTION_PATH, None, query="vdom=root",
        )
        if status != 200 or not isinstance(payload, Mapping):
            raise PasswordChangerHttpTransportError(_UNAVAILABLE)
        rows = payload.get("results")
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            raise PasswordChangerHttpTransportError(_UNAVAILABLE)
        return rows


def _clone_body(source: Mapping[str, object], target_name: str) -> dict[str, object]:
    if source.get("name") != SOURCE_NAME or source.get("type") != "ssh-pwd":
        raise PasswordChangerHttpTransportError(_UNAVAILABLE)
    body: dict[str, object] = {"name": target_name, "description": DESCRIPTION}
    for field in _TOP_FIELDS:
        if field in source:
            body[field] = source[field]
    for stage in _STAGES:
        steps = source.get(stage)
        if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
            raise PasswordChangerHttpTransportError(_UNAVAILABLE)
        if (stage == "change" and len(steps) != 9) or (stage != "change" and steps):
            raise PasswordChangerHttpTransportError(_UNAVAILABLE)
        cleaned = []
        for step in steps:
            if any(key not in _STEP_FIELDS and not key.startswith("q_") for key in step):
                raise PasswordChangerHttpTransportError(_UNAVAILABLE)
            cleaned.append({key: value for key, value in step.items() if key in _STEP_FIELDS})
        body[stage] = cleaned
    return body


def _single_record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    rows = payload.get("results")
    if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], Mapping):
        return rows[0]
    return rows if isinstance(rows, Mapping) else None


def _matches(body: Mapping[str, object], record: Mapping[str, object]) -> bool:
    try:
        return _clone_body({**record, "name": SOURCE_NAME}, str(body["name"])) == body
    except Exception:
        return False


def _digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()
