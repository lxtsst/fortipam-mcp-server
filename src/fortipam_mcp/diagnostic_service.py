"""HTTP-OAuth-only orchestration for fixed FortiPAM V2.3 diagnostics."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Final
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken

from .baseline_drift import (
    BaselineRecord,
    compare_baseline,
)
from .diagnostic_authorization import (
    DiagnosticAuthorizationError,
    DiagnosticPrincipal,
    principal_from_access_token,
)
from .diagnostic_profiles import (
    HA_API_CLI_CORRELATION_CONTRACT,
    HA_API_CLI_CORRELATION_PROFILE_ID,
    HA_API_PROJECTION_CONTRACT,
    HA_API_PROJECTION_REGISTRY,
    correlate_ha_api_cli,
    project_ha_api_baseline,
)
from .diagnostic_store import (
    AuditProfile,
    DiagnosticBaselineStore,
    DiagnosticStoreError,
)
from .evidence_correlation import MAX_EPOCH
from .ha_reconciliation import (
    HA_RECONCILIATION_STATUSES,
    HaReconciliationRuntimeBinding,
    V4_HA_RECONCILIATION_CONTRACT,
)


DIAGNOSTIC_FAILURE = "FortiPAM diagnostic operation failed."
DIAGNOSTIC_UNAVAILABLE = "FortiPAM diagnostics require configured HTTP OAuth."
MIN_HMAC_KEY_BYTES: Final = 32
DIAGNOSTIC_PREFIX: Final = "FORTIPAM_MCP_DIAGNOSTIC_"
DIAGNOSTIC_DB_ENV: Final = f"{DIAGNOSTIC_PREFIX}DB"
DIAGNOSTIC_HMAC_KEY_FILE_ENV: Final = f"{DIAGNOSTIC_PREFIX}HMAC_KEY_FILE"
HA_RECONCILIATION_AUDIT_PROFILE_ID: Final = "ha_reconciliation"
HA_RECONCILIATION_AUDIT_CONTRACT_VERSION: Final = "1"
_HEX_KEY = re.compile(r"^[0-9a-f]{64}$")

Collector = Callable[[], Awaitable[Mapping[str, object]]]
Clock = Callable[[], datetime]


class DiagnosticServiceError(RuntimeError):
    """Stable, non-disclosing diagnostic service failure."""


@dataclass(frozen=True, slots=True)
class DiagnosticServiceSettings:
    """Validated local state and OAuth-resource binding."""

    database_path: Path
    hmac_key: bytes
    expected_resource: str

    def __post_init__(self) -> None:
        if not isinstance(self.database_path, Path) or type(self.expected_resource) is not str:
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        parsed = urlsplit(self.expected_resource)
        if (
            not self.database_path.is_absolute()
            or type(self.hmac_key) is not bytes
            or len(self.hmac_key) < MIN_HMAC_KEY_BYTES
            or parsed.scheme != "https"
            or not parsed.netloc
            or not parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)


def diagnostic_settings_from_environment(
    environment: Mapping[str, str], *, expected_resource: str
) -> DiagnosticServiceSettings | None:
    """Load an all-or-nothing owner-only local diagnostic configuration."""

    database_value = _environment_value(environment, DIAGNOSTIC_DB_ENV)
    key_file_value = _environment_value(
        environment, DIAGNOSTIC_HMAC_KEY_FILE_ENV
    )
    if database_value is None and key_file_value is None:
        return None
    if database_value is None or key_file_value is None:
        raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
    database_path = Path(database_value)
    key_path = Path(key_file_value)
    if not database_path.is_absolute() or not key_path.is_absolute():
        raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
    try:
        _assert_owner_only_key_file(key_path)
        encoded = key_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE) from None
    if not _HEX_KEY.fullmatch(encoded):
        raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
    return DiagnosticServiceSettings(
        database_path=database_path,
        hmac_key=bytes.fromhex(encoded),
        expected_resource=expected_resource,
    )


class FortiPamDiagnosticService:
    """Run only compiled collectors and return closed, non-disclosing states."""

    def __init__(
        self,
        settings: DiagnosticServiceSettings,
        *,
        ha_api_collector: Collector,
        ha_cli_collector: Collector,
        ha_reconciliation: HaReconciliationRuntimeBinding | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(settings, DiagnosticServiceSettings):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        if not callable(ha_api_collector) or not callable(ha_cli_collector):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        if ha_reconciliation is not None and not isinstance(
            ha_reconciliation, HaReconciliationRuntimeBinding
        ):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        if clock is not None and not callable(clock):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        self._settings = settings
        self._ha_api_collector = ha_api_collector
        self._ha_cli_collector = ha_cli_collector
        self._ha_reconciliation = ha_reconciliation
        self._clock = clock or (lambda: datetime.now(UTC))

    async def create_ha_baseline(
        self, access_token: AccessToken | None, baseline_id: str
    ) -> dict[str, str]:
        """Capture the fixed HA API projection into an immutable local baseline."""

        principal = self._principal(access_token)
        moment = self._now()
        store = self._store(principal)
        try:
            result = await self._ha_api_collector()
            envelope = project_ha_api_baseline(result, moment)
            store.create(
                baseline_id,
                BaselineRecord(
                    envelope=envelope,
                    digest=envelope.comparison_digest,
                ),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            self._append_rejected_create(store, moment)
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None
        return {"status": "created"}

    async def compare_ha_baseline(
        self, access_token: AccessToken | None, baseline_id: str
    ) -> dict[str, str]:
        """Compare one fresh fixed HA API projection with an immutable baseline."""

        principal = self._principal(access_token)
        moment = self._now()
        store = self._store(principal)
        try:
            result = await self._ha_api_collector()
            envelope = project_ha_api_baseline(result, moment)
            drift = compare_baseline(
                store,
                baseline_id,
                envelope.canonical,
                HA_API_PROJECTION_REGISTRY,
                now=moment,
            )
            store.append_event(
                "baseline_compare",
                HA_API_PROJECTION_CONTRACT.contract_id,
                HA_API_PROJECTION_CONTRACT.contract_id,
                HA_API_PROJECTION_CONTRACT.version,
                drift.status,
                moment,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None
        return drift.as_dict()

    async def correlate_ha_api_cli(
        self, access_token: AccessToken | None
    ) -> dict[str, str]:
        """Correlate only the fixed API and CLI HA configuration summaries."""

        principal = self._principal(access_token)
        store = self._store(principal)
        try:
            api_result, cli_result = await asyncio.gather(
                self._ha_api_collector(),
                self._ha_cli_collector(),
            )
            moment = self._now()
            epoch = int(moment.timestamp())
            result = correlate_ha_api_cli(
                api_result,
                cli_result,
                api_evidence_ref=self._evidence_ref(principal, epoch, "api"),
                cli_evidence_ref=self._evidence_ref(principal, epoch, "cli"),
                tenant_scope=f"tenant-{principal.namespace_digest[:32]}",
                now_epoch=epoch,
            )
            relationship = result["relationship_class"]
            store.append_event(
                "evidence_correlate",
                HA_API_CLI_CORRELATION_PROFILE_ID,
                HA_API_CLI_CORRELATION_CONTRACT.contract_id,
                HA_API_CLI_CORRELATION_CONTRACT.contract_version,
                relationship,
                moment,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None
        return {"status": relationship}

    async def reconcile_ha(
        self, access_token: AccessToken | None
    ) -> dict[str, str]:
        """Run the internal HA assessment behind OAuth and bounded audit."""

        principal = self._principal(access_token)
        if self._ha_reconciliation is None:
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        moment = self._now()
        store = self._store(principal)
        try:
            result = await self._ha_reconciliation.assess()
            status = result.get("assessment_status")
            if type(status) is not str or status not in HA_RECONCILIATION_STATUSES:
                raise ValueError
            store.append_event(
                "ha_reconcile",
                HA_RECONCILIATION_AUDIT_PROFILE_ID,
                V4_HA_RECONCILIATION_CONTRACT,
                HA_RECONCILIATION_AUDIT_CONTRACT_VERSION,
                status,
                moment,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            self._append_rejected_reconciliation(store, moment)
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None
        return {"status": status}

    def _principal(self, access_token: AccessToken | None) -> DiagnosticPrincipal:
        try:
            return principal_from_access_token(
                access_token,  # type: ignore[arg-type]
                expected_resource=self._settings.expected_resource,
                namespace_hmac_key=self._settings.hmac_key,
            )
        except DiagnosticAuthorizationError:
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE) from None

    def _store(self, principal: DiagnosticPrincipal) -> DiagnosticBaselineStore:
        try:
            return DiagnosticBaselineStore(
                self._settings.database_path,
                HA_API_PROJECTION_REGISTRY,
                principal.namespace_digest,
                self._settings.hmac_key,
                audit_profiles=(
                    AuditProfile(
                        HA_API_PROJECTION_CONTRACT.contract_id,
                        HA_API_PROJECTION_CONTRACT.contract_id,
                        HA_API_PROJECTION_CONTRACT.version,
                        frozenset(
                            {
                                "baseline_create",
                                "baseline_compare",
                                "store_verify",
                            }
                        ),
                    ),
                    AuditProfile(
                        HA_API_CLI_CORRELATION_PROFILE_ID,
                        HA_API_CLI_CORRELATION_CONTRACT.contract_id,
                        HA_API_CLI_CORRELATION_CONTRACT.contract_version,
                        frozenset({"evidence_correlate"}),
                    ),
                    AuditProfile(
                        HA_RECONCILIATION_AUDIT_PROFILE_ID,
                        V4_HA_RECONCILIATION_CONTRACT,
                        HA_RECONCILIATION_AUDIT_CONTRACT_VERSION,
                        frozenset({"ha_reconcile"}),
                    ),
                ),
            )
        except DiagnosticStoreError:
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE) from None

    def _now(self) -> datetime:
        try:
            moment = self._clock()
            if (
                not isinstance(moment, datetime)
                or moment.tzinfo is None
                or moment.utcoffset() != UTC.utcoffset(moment)
            ):
                raise ValueError
            epoch = int(moment.timestamp())
            if not 0 <= epoch <= MAX_EPOCH:
                raise ValueError
            return moment.astimezone(UTC)
        except Exception:
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None

    def _append_rejected_create(
        self, store: DiagnosticBaselineStore, occurred_at: datetime
    ) -> None:
        try:
            store.append_event(
                "baseline_create",
                HA_API_PROJECTION_CONTRACT.contract_id,
                HA_API_PROJECTION_CONTRACT.contract_id,
                HA_API_PROJECTION_CONTRACT.version,
                "rejected",
                occurred_at,
            )
        except DiagnosticStoreError:
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None

    def _append_rejected_reconciliation(
        self, store: DiagnosticBaselineStore, occurred_at: datetime
    ) -> None:
        try:
            store.append_event(
                "ha_reconcile",
                HA_RECONCILIATION_AUDIT_PROFILE_ID,
                V4_HA_RECONCILIATION_CONTRACT,
                HA_RECONCILIATION_AUDIT_CONTRACT_VERSION,
                "rejected",
                occurred_at,
            )
        except DiagnosticStoreError:
            raise DiagnosticServiceError(DIAGNOSTIC_FAILURE) from None

    def _evidence_ref(
        self, principal: DiagnosticPrincipal, epoch: int, source: str
    ) -> str:
        payload = (
            b"evidence-reference\x00"
            + bytes.fromhex(principal.namespace_digest)
            + epoch.to_bytes(8, "big")
            + source.encode("ascii")
        )
        digest = hmac.new(
            self._settings.hmac_key, payload, hashlib.sha256
        ).hexdigest()
        return f"ref-{digest[:32]}"


def _environment_value(
    environment: Mapping[str, str], name: str
) -> str | None:
    value = environment.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _assert_owner_only_key_file(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        if not current.exists():
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
    info = os.lstat(path)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)


__all__ = [
    "DIAGNOSTIC_FAILURE",
    "DIAGNOSTIC_PREFIX",
    "DIAGNOSTIC_UNAVAILABLE",
    "DiagnosticServiceError",
    "DiagnosticServiceSettings",
    "FortiPamDiagnosticService",
    "HA_RECONCILIATION_AUDIT_CONTRACT_VERSION",
    "HA_RECONCILIATION_AUDIT_PROFILE_ID",
    "diagnostic_settings_from_environment",
]
