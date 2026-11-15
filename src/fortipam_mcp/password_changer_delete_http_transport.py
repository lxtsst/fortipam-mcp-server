"""Fixed FortiPAM 7.0 REST recovery for one privately bound Unix clone."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
from urllib.parse import quote

from .password_changer_http_transport import (
    COLLECTION_PATH, SOURCE_NAME, _NAME, _clone_body, _digest, _matches,
    _single_record,
)
from .password_changer_reference_ssh_transport import (
    FortiPamPasswordChangerReferenceSshTransport,
    PasswordChangerReferenceReadback,
)
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)


_UNAVAILABLE = "FortiPAM V4 Unix Password Changer recovery is unavailable."


class PasswordChangerDeleteHttpTransportError(RuntimeError):
    """Stable non-disclosing fixed recovery failure."""


@dataclass(frozen=True, slots=True)
class PasswordChangerDeleteInspection:
    target_exists: bool
    exact_clone_matches: bool
    references_known_zero: bool
    target_digest: str
    source_digest: str

    @property
    def eligible(self) -> bool:
        return self.target_exists and self.exact_clone_matches and self.references_known_zero


@dataclass(frozen=True, slots=True)
class PasswordChangerDeleteReadback:
    delete_accepted: bool
    detail_absent: bool
    collection_absent: bool
    source_preserved: bool
    references_absent: bool

    @property
    def verified(self) -> bool:
        return all((
            self.delete_accepted, self.detail_absent, self.collection_absent,
            self.source_preserved, self.references_absent,
        ))


class FortiPamUnixPasswordChangerDeleteHttpTransport:
    """Delete only an exact clone with live REST and SSH reference checks."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        target_name: str,
        references: FortiPamPasswordChangerReferenceSshTransport,
    ) -> None:
        if not isinstance(target_name, str) or _NAME.fullmatch(target_name) is None:
            raise PasswordChangerDeleteHttpTransportError(_UNAVAILABLE)
        if not isinstance(references, FortiPamPasswordChangerReferenceSshTransport):
            raise PasswordChangerDeleteHttpTransportError(_UNAVAILABLE)
        self._client = FortiPamSecretMetadataHttpTransport(config)
        self._target_name = target_name
        self._references = references

    def inspect(self) -> PasswordChangerDeleteInspection:
        try:
            if self._client.read_product_version_and_build() != ("7.0.0", 29):
                raise ValueError
            rows = self._collection()
            sources = [row for row in rows if row.get("name") == SOURCE_NAME]
            targets = [row for row in rows if row.get("name") == self._target_name]
            if len(sources) != 1 or len(targets) > 1:
                raise ValueError
            source = sources[0]
            expected = _clone_body(source, self._target_name)
            source_digest = _digest(source)
            if not targets:
                return PasswordChangerDeleteInspection(
                    False, False, False, "0" * 64, source_digest,
                )
            status, payload = self._client._request(
                "GET", self._detail_path(), None, query="vdom=root",
            )
            detail = _single_record(payload) if status == 200 else None
            exact = detail is not None and _matches(expected, detail) and _matches(
                expected, targets[0],
            )
            if not exact:
                raise ValueError
            references = self._references.inspect(self._target_name)
            if not isinstance(references, PasswordChangerReferenceReadback):
                raise ValueError
            return PasswordChangerDeleteInspection(
                True, True, references.verified_zero, _digest(targets[0]), source_digest,
            )
        except Exception:
            raise PasswordChangerDeleteHttpTransportError(_UNAVAILABLE) from None

    def delete_and_readback(
        self, expected: PasswordChangerDeleteInspection,
    ) -> PasswordChangerDeleteReadback:
        """Recheck the complete bound baseline, then issue at most one DELETE."""

        try:
            if not isinstance(expected, PasswordChangerDeleteInspection) or not expected.eligible:
                raise ValueError
            current = self.inspect()
            if (
                not current.eligible
                or not hmac.compare_digest(current.target_digest, expected.target_digest)
                or not hmac.compare_digest(current.source_digest, expected.source_digest)
            ):
                raise ValueError
            status, payload = self._client._request(
                "DELETE", self._detail_path(), None, query="vdom=root",
            )
            accepted = status == 200 and isinstance(payload, dict) and payload.get(
                "http_status"
            ) in (None, 200)
            detail_status, _ = self._client._request(
                "GET", self._detail_path(), None, query="vdom=root",
            )
            rows_after = self._collection()
            sources_after = [row for row in rows_after if row.get("name") == SOURCE_NAME]
            target_absent = not any(row.get("name") == self._target_name for row in rows_after)
            refs = self._references.inspect(self._target_name)
            return PasswordChangerDeleteReadback(
                accepted,
                detail_status == 404,
                target_absent,
                len(sources_after) == 1 and hmac.compare_digest(
                    _digest(sources_after[0]), expected.source_digest,
                ),
                isinstance(refs, PasswordChangerReferenceReadback) and refs.verified_zero,
            )
        except Exception:
            raise PasswordChangerDeleteHttpTransportError(_UNAVAILABLE) from None

    def _detail_path(self) -> str:
        return f"{COLLECTION_PATH}/{quote(self._target_name, safe='')}"

    def _collection(self) -> list[dict[str, object]]:
        status, payload = self._client._request(
            "GET", COLLECTION_PATH, None, query="vdom=root",
        )
        rows = payload.get("results") if isinstance(payload, dict) else None
        if status != 200 or not isinstance(rows, list) or not all(
            isinstance(row, dict) for row in rows
        ):
            raise PasswordChangerDeleteHttpTransportError(_UNAVAILABLE)
        return rows


__all__ = [
    "FortiPamUnixPasswordChangerDeleteHttpTransport",
    "PasswordChangerDeleteHttpTransportError",
    "PasswordChangerDeleteInspection",
    "PasswordChangerDeleteReadback",
]
