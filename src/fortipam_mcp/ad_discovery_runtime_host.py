"""Explicit protected startup composition for the fixed BP014 AD candidate."""

from collections.abc import Callable, Mapping
import hmac
from pathlib import Path
import time

from .ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoPromoter, AdDiscoveryLabAutoRunnerFactory
from .ad_discovery_mcp_action import ProtectedAdDiscoveryMcpAction, load_v4_ad_discovery_execution_feature
from .ad_discovery_runtime_config import load_ad_discovery_runtime_binding
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .local_oauth import LocalOAuthProvider
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider
from .owner_domain_runtime import owner_domain_transport
from .secret_create_lab_auto_runtime import _read_owner_only_authority_key
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_confirmation_http import V4ConfirmationSettings
from .v4_runtime_host import (
    V4PlanHostComponents, V4RuntimeHostError, V4SyntheticHostSettings,
    ad_discovery_v4_plan_host_factory,
)


AD_DISCOVERY_RUNTIME_PREFIX = "FORTIPAM_MCP_V4_AD_DISCOVERY_"
_UNAVAILABLE = "AD Discovery protected startup composition is unavailable."
PlanHostFactory = Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]
ExecutionFactory = Callable[[V4PlanHostComponents], ProtectedAdDiscoveryMcpAction]


def _required(environment: Mapping[str, str], suffix: str) -> str:
    value = environment.get(AD_DISCOVERY_RUNTIME_PREFIX + suffix)
    if type(value) is not str or not value or value != value.strip():
        raise ValueError
    return value


def _path(environment: Mapping[str, str], suffix: str) -> Path:
    path = Path(_required(environment, suffix))
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    # Alias paths must not evade separation of authority and durable stores.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError
    return path


def _flag(environment: Mapping[str, str], suffix: str) -> bool:
    value = environment.get(AD_DISCOVERY_RUNTIME_PREFIX + suffix, "false")
    if value not in ("true", "false"):
        raise ValueError
    return value == "true"


def build_ad_discovery_runtime_host(
    settings: V4SyntheticHostSettings, environment: Mapping[str, str], *,
    clock: Callable[[], int] | None = None,
) -> tuple[PlanHostFactory, ExecutionFactory | None]:
    """Bind private selectors and lazy Owner references without authentication.

    The existing server-held standing lab authority remains independent of
    browser intent, the input file, and the execution Tool feature.
    """
    try:
        if settings.host_mode != "source-backed-ad-discovery":
            raise ValueError
        feature = load_v4_ad_discovery_execution_feature(environment)
        gate = _flag(environment, "EXECUTION_ENABLED")
        standing = _flag(environment, "STANDING_LAB_AUTHORIZATION")
        if gate and not feature:
            raise ValueError
        binding = load_ad_discovery_runtime_binding(_path(environment, "BINDING_FILE"))
        config = load_secret_metadata_http_transport_config(environment)
        credentials = owner_login_provider(environment)
        if credentials is None:
            raise ValueError
        owner = owner_domain_transport(
            config, binding.domain.create_binding, credentials, allow_secret_create=False,
        )
        writer = FortiPamDiscoveryEntryCreateHttpTransport(config)
        runtime_clock = clock if clock is not None else lambda: int(time.time())
        plan_factory = ad_discovery_v4_plan_host_factory(
            settings, binding=binding, owner_transport=owner,
            source_transport=writer, clock=runtime_clock,
        )
        if not feature:
            return plan_factory, None
        authority_path = _path(environment, "AUTHORITY_KEY_FILE")
        execution_path = _path(environment, "EXECUTION_STATE_DB")
        execution_key_path = _path(environment, "EXECUTION_STATE_HMAC_KEY_FILE")
        paths = [authority_path, execution_path, execution_key_path,
                 settings.planning_database_path, settings.planning_hmac_key_path]
        planning_keys = [settings.planning_hmac_key_path]
        for authority in (settings.reference_authority, settings.scheme_draft_authority,
                          settings.planning_checkpoint):
            if authority is not None:
                paths.extend((authority.database_path, authority.hmac_key_path))
                planning_keys.append(authority.hmac_key_path)
        if len({path.resolve() for path in paths}) != len(paths):
            raise ValueError
        authority_key = _read_owner_only_authority_key(authority_path)
        execution_key = _read_owner_only_authority_key(execution_key_path)
        if not 32 <= len(execution_key) <= 128 or hmac.compare_digest(authority_key, execution_key):
            raise ValueError
        for key_path in planning_keys:
            key = _read_owner_only_authority_key(key_path)
            if hmac.compare_digest(authority_key, key) or hmac.compare_digest(execution_key, key):
                raise ValueError
        environment_ref = _required(environment, "AUTHORIZED_ENVIRONMENT_REF")
        scope_ref = _required(environment, "AUTHORIZED_SCOPE_REF")
        if (environment_ref != binding.domain.environment_ref
            or scope_ref != binding.domain.scope_ref):
            raise ValueError
        store = PersistentM4ExecutionStateStore(execution_path, execution_key_path)
        if not hmac.compare_digest(store._key, execution_key):
            raise ValueError

        def execution_factory(components: V4PlanHostComponents) -> ProtectedAdDiscoveryMcpAction:
            try:
                source = components.ad_discovery_projection_source
                if (source is None or source._binding != binding
                    or source._owner is not owner or source._source_transport is not writer):
                    raise ValueError
                promoter = AdDiscoveryLabAutoPromoter(
                    authority_key, projection_source=source,
                    authorized_environment_ref=environment_ref, authorized_scope_ref=scope_ref,
                    standing_lab_authorization=standing,
                )
                runner = AdDiscoveryLabAutoRunnerFactory(
                    promoter=promoter, execution_store=store, source_transport=writer,
                    owner_config=config, owner_credentials=credentials, clock=runtime_clock,
                    execution_gate_open=gate,
                )
                return ProtectedAdDiscoveryMcpAction(
                    components.plan_services, components.bind_ad_discovery_action_coordinator(runner),
                    authorized_environment_ref=environment_ref, authorized_scope_ref=scope_ref,
                    execution_enabled=gate,
                )
            except Exception:
                raise V4RuntimeHostError(_UNAVAILABLE) from None

        def protected_plan_factory(
            provider: LocalOAuthProvider, confirmation: V4ConfirmationSettings,
        ) -> V4PlanHostComponents:
            try:
                confirmation_paths = (confirmation.database_path,
                    confirmation.store_hmac_key_path, confirmation.receipt_hmac_key_path)
                combined = [*paths, *confirmation_paths]
                if len({path.resolve() for path in combined}) != len(combined):
                    raise ValueError
                for key_path in confirmation_paths[1:]:
                    key = _read_owner_only_authority_key(key_path)
                    if (hmac.compare_digest(authority_key, key)
                        or hmac.compare_digest(execution_key, key)):
                        raise ValueError
                return plan_factory(provider, confirmation)
            except Exception:
                raise V4RuntimeHostError(_UNAVAILABLE) from None

        return protected_plan_factory, execution_factory
    except Exception:
        raise V4RuntimeHostError(_UNAVAILABLE) from None


__all__ = ["AD_DISCOVERY_RUNTIME_PREFIX", "build_ad_discovery_runtime_host"]
