"""Private verified-MCP requester binding for the fixed service candidate.

Only trusted composition supplies settings/providers. No Tool accepts a token,
principal or digest, and no normal runtime registration is added here. This
boundary cannot qualify product sources, adopt another requester's lineage or
grant execution merely because HTTP authentication succeeded.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any, Literal

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from v4_planning import canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import C3MaterialBinding, _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore
from .onboarding_execution_mcp_action import onboarding_execution_principal_from_access_token
from .runtime_profile import RuntimeProfile
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .v4_plan_runtime import V4PlanningAuthorizationSettings
from .windows_execution_secret_contract import WindowsExecutionSecretDefaults
from .windows_service_credential_authority import WindowsServiceCredentialLabAuthority
from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from .windows_service_credential_contract import WindowsServiceCredentialBinding
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerBinding, WindowsServiceCredentialOwnerSession
from .windows_service_credential_recovery import WindowsServiceCredentialRecovery
from .windows_service_credential_recovery_authority import WindowsServiceCredentialRemovalLabAuthority

_ERROR = "The private Windows service credential server identity is unavailable."
_DOMAIN = b"service-credential-verified-mcp-requester/v1\x00"
_Purpose = Literal["create", "recovery"]


class WindowsServiceCredentialServerIdentityError(ValueError):
    """Categorical refusal without token, human, client or resource content."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialServerIdentitySnapshot(_OpaqueC3Object):
    requester_digest: str
    transport_digest: str
    context_digest: str
    observed_at: int
    expires_at: int
    purpose: _Purpose
    _token_context: str
    _signature: str


class WindowsServiceCredentialServerIdentity(_OpaqueC3Object):
    """Read the SDK's verified request context, never caller-authored identity."""
    def __init__(self, settings: V4PlanningAuthorizationSettings, *, runtime_profile: RuntimeProfile,
            environment_ref: str, scope_ref: str, audience_ref: str, enabled: bool = False,
            token_provider: Callable[[], AccessToken | None] = get_access_token,
            clock: Callable[[], int] = lambda:int(time.time())) -> None:
        try:
            if (type(settings) is not V4PlanningAuthorizationSettings
                    or type(runtime_profile) is not RuntimeProfile or runtime_profile is not RuntimeProfile.V4_CONTROLLED
                    or settings.insecure_private_ip_lab is not False or type(enabled) is not bool
                    or not callable(token_provider) or not callable(clock)):
                raise ValueError
            settings.__post_init__()
            for value in (environment_ref,scope_ref,audience_ref):require_ref(value,"service_server_scope")
            self._settings = settings
            self._profile = runtime_profile
            self._environment,self._scope,self._audience = environment_ref,scope_ref,audience_ref
            self._enabled,self._provider,self._clock = enabled,token_provider,clock
            self._provider_pin,self._clock_pin = token_provider,clock
            self._key = bytearray(secrets.token_bytes(32))
            self._namespace = self._context()
            self._closed = self._failed_clock = False
            self._last = -1
            self._lock = RLock()
        except Exception:
            if hasattr(self,"_key"):_zeroize_mutable(self._key)
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def _context(self) -> str:
        self._settings.__post_init__()
        return canonical_digest(dict(resource=self._settings.expected_resource,
            namespace_key=hashlib.sha256(self._settings.namespace_hmac_key).hexdigest(),
            insecure=self._settings.insecure_private_ip_lab,profile=str(self._profile),
            environment=self._environment,scope=self._scope,audience=self._audience))

    def _now(self) -> int:
        if (self._closed or self._failed_clock or self._clock is not self._clock_pin
                or self._provider is not self._provider_pin or self._enabled is not True
                or self._context()!=self._namespace or self._profile is not RuntimeProfile.V4_CONTROLLED):raise ValueError
        now=self._clock()
        if type(now) is not int or now<0 or now<self._last:
            self._failed_clock=True
            raise ValueError
        self._last=now
        return now

    def _observe(self) -> tuple[str,str,str,int,int]:
        now=self._now()
        token=self._provider()
        principal=onboarding_execution_principal_from_access_token(token,self._settings)
        if not isinstance(token,AccessToken) or type(token.expires_at) is not int or token.expires_at<=now:
            raise ValueError
        token_context=hmac.new(self._key,_DOMAIN+b"token\x00"+token.token.encode(),hashlib.sha256).hexdigest()
        return principal.requester.digest,principal.transport_namespace_digest,token_context,token.expires_at,now

    def _signature(self, value: WindowsServiceCredentialServerIdentitySnapshot) -> str:
        payload=dict(requester=value.requester_digest,transport=value.transport_digest,context=value.context_digest,
            observed=value.observed_at,expires=value.expires_at,purpose=value.purpose,
            token_context=value._token_context,instance=hex(id(value)),namespace=self._namespace)
        return hmac.new(self._key,_DOMAIN+canonical_digest(payload).encode(),hashlib.sha256).hexdigest()

    def capture(self, *, purpose: _Purpose) -> WindowsServiceCredentialServerIdentitySnapshot:
        try:
            with self._lock:
                if type(purpose) is not str or purpose not in ("create","recovery"):raise ValueError
                requester,transport,token_context,expires,now=self._observe()
                context=canonical_digest(dict(contract="fixed-service-credential-server-identity-v1",
                    namespace=self._namespace,requester=requester,transport=transport,token_context=token_context,
                    purpose=purpose,expires=expires))
                value=WindowsServiceCredentialServerIdentitySnapshot(requester,transport,context,now,expires,purpose,token_context,"")
                object.__setattr__(value,"_signature",self._signature(value))
                return value
        except Exception:
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def require_current(self, snapshot: WindowsServiceCredentialServerIdentitySnapshot, *, purpose: _Purpose,
            grant_expires_at: int | None = None) -> None:
        try:
            with self._lock:
                requester,transport,token_context,expires,now=self._observe()
                if (type(snapshot) is not WindowsServiceCredentialServerIdentitySnapshot
                        or purpose not in ("create","recovery") or snapshot.purpose!=purpose
                        or not hmac.compare_digest(snapshot._signature,self._signature(snapshot))
                        or (snapshot.requester_digest,snapshot.transport_digest,snapshot._token_context,snapshot.expires_at)
                            != (requester,transport,token_context,expires)
                        or not snapshot.observed_at<=now<snapshot.expires_at
                        or grant_expires_at is not None and (type(grant_expires_at) is not int
                            or not now<grant_expires_at<=snapshot.expires_at)):
                    raise ValueError
        except Exception:
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def require_original_requester(self, snapshot: WindowsServiceCredentialServerIdentitySnapshot, *,
            original_requester_digest: str) -> None:
        """Never relabel a configured lab principal as the authenticated human."""
        try:
            self.require_current(snapshot,purpose=snapshot.purpose)
            require_digest(original_requester_digest,"original_service_requester")
            if original_requester_digest!=snapshot.requester_digest:
                raise ValueError
        except Exception:
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def create_authority(self, snapshot: WindowsServiceCredentialServerIdentitySnapshot, *,
            profile: WindowsServiceCredentialBinding, defaults: WindowsExecutionSecretDefaults,
            material_binding: C3MaterialBinding, execution_store: PersistentM4ExecutionStateStore,
            material_store: PersistentMaterialUseStateStore, authority_key_file: Path, witness_key_file: Path,
            native_source_context_digest: str, check_native_source: Callable[[], bool],
            owner_binding: WindowsServiceCredentialOwnerBinding, execution_enabled: bool = False) -> WindowsServiceCredentialLabAuthority:
        """Derive requester/transport/scope server-side; native guards stay required."""
        try:
            if execution_enabled is not True:raise ValueError
            self.require_current(snapshot,purpose="create")
            require_digest(native_source_context_digest,"native_service_source")
            if not callable(check_native_source):raise ValueError
            holder:list[WindowsServiceCredentialLabAuthority]=[]
            def source() -> bool:
                try:
                    expiry=holder[0]._preview.expires_at if holder and holder[0]._preview is not None else self._now()+60
                    self.require_current(snapshot,purpose="create",grant_expires_at=expiry)
                    if check_native_source() is not True:return False
                    self.require_current(snapshot,purpose="create",grant_expires_at=expiry)
                    return True
                except Exception:return False
            authority=WindowsServiceCredentialLabAuthority(profile=profile,defaults=defaults,material_binding=material_binding,
                execution_store=execution_store,material_store=material_store,authority_key_file=authority_key_file,
                witness_key_file=witness_key_file,source_context_digest=canonical_digest(dict(native=native_source_context_digest,
                    server=snapshot.context_digest)),requester_digest=snapshot.requester_digest,
                transport_digest=snapshot.transport_digest,environment_ref=self._environment,scope_ref=self._scope,
                audience_ref=self._audience,check_source=source,owner_binding=owner_binding,
                execution_enabled=execution_enabled,clock=self._clock)
            holder.append(authority)
            return authority
        except Exception:
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def recovery_components(self, snapshot: WindowsServiceCredentialServerIdentitySnapshot, *,
            custody: WindowsServiceCredentialBirthCustody, execution_store: PersistentM4ExecutionStateStore,
            authority_key_file: Path, witness_key_file: Path,
            config: SecretMetadataHttpTransportConfig, owner_session: WindowsServiceCredentialOwnerSession,
            check_native_source: Callable[[], bool], execution_enabled: bool = False,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic
            ) -> tuple[WindowsServiceCredentialRemovalLabAuthority, WindowsServiceCredentialRecovery]:
        """Assemble a real independent issuer/runtime with identity always checked.

        No unguarded issuer escapes this composition. The original requester is
        read from custody; a fresh token/client can recover the same human's
        original object, using separate stores, keys and Owner session.
        """
        authority: WindowsServiceCredentialRemovalLabAuthority | None = None
        try:
            if execution_enabled is not True:raise ValueError
            self.require_current(snapshot,purpose="recovery")
            self.require_original_requester(snapshot,original_requester_digest=custody._plan.requester_digest)
            holder:list[WindowsServiceCredentialRecovery]=[]
            def expiry() -> int:
                return holder[0]._preview.expires_at if holder and holder[0]._preview is not None else self._now()+30
            source=self.source_guard(snapshot,purpose="recovery",native_guard=check_native_source,grant_expiry=expiry)
            if source() is not True:raise ValueError
            authority=WindowsServiceCredentialRemovalLabAuthority(custody,execution_store=execution_store,
                authority_key_file=authority_key_file,witness_key_file=witness_key_file,
                environment_ref=self._environment,scope_ref=self._scope,audience_ref=self._audience,
                requester_digest=snapshot.requester_digest,transport_digest=snapshot.transport_digest,
                execution_enabled=execution_enabled,clock=self._clock)
            runtime=WindowsServiceCredentialRecovery(custody,execution_store=execution_store,
                witness_key_file=witness_key_file,authorization_verifier=authority,execution_enabled=execution_enabled,
                config=config,source_guard=source,owner_session=owner_session,connection_factory=connection_factory,
                clock=self._clock,http_clock=http_clock)
            holder.append(runtime)
            return authority,runtime
        except Exception:
            if authority is not None:authority.close()
            raise WindowsServiceCredentialServerIdentityError(_ERROR) from None

    def source_guard(self, snapshot: WindowsServiceCredentialServerIdentitySnapshot, *, purpose: _Purpose,
            native_guard: Callable[[], bool], grant_expiry: Callable[[], int | None] = lambda:None) -> Callable[[], bool]:
        """Recheck the current SDK context throughout an independently owned runtime."""
        self.require_current(snapshot,purpose=purpose)
        if not callable(native_guard) or not callable(grant_expiry):
            raise WindowsServiceCredentialServerIdentityError(_ERROR)
        def check() -> bool:
            try:
                self.require_current(snapshot,purpose=purpose,grant_expires_at=grant_expiry())
                if native_guard() is not True:return False
                self.require_current(snapshot,purpose=purpose,grant_expires_at=grant_expiry())
                return True
            except Exception:return False
        return check

    def close(self) -> None:
        with self._lock:
            self._closed=True
            _zeroize_mutable(self._key)
