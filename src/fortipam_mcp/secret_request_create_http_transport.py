"""One-shot source-pinned FortiPAM Secret-request create candidate.

This low-level transport is intentionally not registered as an MCP Tool.  It
validates the exact default object, captures the authenticated creator view,
sends one frontend-equivalent POST, and binds the result only through one
unambiguous creator-view delta.  Any uncertainty is terminal and requires
reconciliation; the instance never retries a write.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import http.client
import json
import logging
import os
from pathlib import Path
import stat
from threading import Lock
import time
from typing import Literal, Protocol
from urllib.parse import urlsplit

from v4_planning.models import require_digest, require_ref

from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)
from .secret_request_actor_http_transport import (
    FortiPamSecretRequestActorHttpTransport,
)
from .secret_request_collection_http_transport import (
    FortiPamSecretRequestCollectionHttpTransport,
    SecretRequestCollectionHttpTransportError,
    SecretRequestCollectionRecord,
    SecretRequestCreatorSnapshot,
    bind_new_secret_request,
)
from .secret_request_create_contract import (
    REQUEST_CREATE_METHOD,
    REQUEST_CREATE_PATH,
    REQUEST_CREATE_POST_QUERY,
    SecretRequestCustomField,
    SecretRequestCreateInput,
    SecretRequestDefaultEvidence,
)
from .secret_request_default_http_transport import (
    FortiPamSecretRequestDefaultHttpTransport,
)
from .secret_request_http_transport import (
    FortiPamSecretRequestHttpTransport,
    SecretRequestObservation,
)
from .v4_plan_runtime import V4PlanningPrincipal
from .secret_request_create_invocation_witness import (
    SecretRequestCreateInvocationWitness, SecretRequestCreateInvocationWitnessSink,
)


_UNAVAILABLE = "The FortiPAM Secret-request create transport is unavailable."
_DISPATCH_CLAIM_CONTRACT = "fortipam-v4-secret-request-create-claim-v1"
REQUEST_CREATE_INTENT_CONTRACT = "fortipam-v4-secret-request-create-intent-v1"
REQUEST_CREATE_INTENT_VERSION = "1.0.0"
_MIN_HMAC_KEY_BYTES = 32
_MAX_BINDING_BYTES = 524_288
_MAX_CLAIM_BYTES = 4096
_TERMINAL_OUTCOMES = frozenset({"bound", "reconciliation_required"})
_FAILURE_STAGES = frozenset(
    {
        "none",
        "intent_resolution",
        "dispatch_claim_preflight",
        "api_actor_preflight",
        "default_read",
        "creator_snapshot_before",
        "dispatch_claim",
        "post",
        "creator_snapshot_after",
        "delta_bind",
        "detail_read",
        "requester_session_cleanup",
        "invocation_witness",
    }
)
_HTTP_STATUS_CLASSES = frozenset(
    {"none", "http_4xx", "http_5xx", "http_other"}
)


class SecretRequestCreateDispatchClaimError(RuntimeError):
    """Stable failure for an unavailable or already-consumed create claim."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreateBinding:
    """Protected same-requester and fixed-scope binding supplied by the Host."""

    intent_ref: str
    fortipam_requester: str
    requester_digest: str
    environment_ref: str
    scope_ref: str
    expires_at: int
    submission_mode: Literal["same_requester"] = "same_requester"

    def __post_init__(self) -> None:
        try:
            require_ref(self.intent_ref, "intent_ref")
            require_digest(self.requester_digest, "requester_digest")
            require_ref(self.environment_ref, "environment_ref")
            require_ref(self.scope_ref, "scope_ref")
        except (TypeError, ValueError) as exc:
            raise ValueError(_UNAVAILABLE) from exc
        if (
            not isinstance(self.fortipam_requester, str)
            or not self.fortipam_requester
            or self.fortipam_requester != self.fortipam_requester.strip()
            or len(self.fortipam_requester.encode("utf-8")) > 128
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.fortipam_requester
            )
            or type(self.expires_at) is not int
            or self.expires_at <= 0
            or self.submission_mode != "same_requester"
        ):
            raise ValueError(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreatePreparedIntent:
    """Protected intent loaded locally; only its opaque reference may be public."""

    binding: SecretRequestCreateBinding
    request: SecretRequestCreateInput

    def __post_init__(self) -> None:
        if (
            not isinstance(self.binding, SecretRequestCreateBinding)
            or not isinstance(self.request, SecretRequestCreateInput)
            or self.request.requester != self.binding.fortipam_requester
        ):
            raise ValueError(_UNAVAILABLE)


class OwnerOnlySecretRequestCreateBindingResolver:
    """Load one fixed protected intent from an owner-only local file."""

    __slots__ = ("_clock", "_path")

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._path = Path(path)
        self._clock = clock or (lambda: int(time.time()))
        if not self._path.is_absolute() or not callable(self._clock):
            raise ValueError(_UNAVAILABLE)

    def resolve(
        self,
        *,
        intent_ref: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
    ) -> SecretRequestCreatePreparedIntent:
        payload = self._load()
        expected = {
            "contract",
            "version",
            "intent_ref",
            "fortipam_requester",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "expires_at",
            "submission_mode",
            "secret_id",
            "request_type",
            "start_after_approve",
            "start_time",
            "expiration_time",
            "duration",
            "comments",
            "timezone",
            "job_name",
            "custom_fields",
        }
        if (
            set(payload) != expected
            or payload.get("contract") != REQUEST_CREATE_INTENT_CONTRACT
            or payload.get("version") != REQUEST_CREATE_INTENT_VERSION
        ):
            raise ValueError(_UNAVAILABLE)
        try:
            binding = SecretRequestCreateBinding(
                intent_ref=_mapping_text(payload, "intent_ref"),
                fortipam_requester=_mapping_text(payload, "fortipam_requester"),
                requester_digest=_mapping_text(payload, "requester_digest"),
                environment_ref=_mapping_text(payload, "environment_ref"),
                scope_ref=_mapping_text(payload, "scope_ref"),
                expires_at=_mapping_int(payload, "expires_at"),
                submission_mode=_same_requester_mode(payload),
            )
            request = SecretRequestCreateInput(
                requester=binding.fortipam_requester,
                secret_id=_mapping_int(payload, "secret_id"),
                request_type=_request_type(payload),
                start_after_approve=_start_after_approve(payload),
                start_time=_mapping_text(payload, "start_time"),
                expiration_time=_mapping_text(payload, "expiration_time"),
                duration=_mapping_int(payload, "duration"),
                comments=_mapping_text(payload, "comments"),
                timezone=_mapping_text(payload, "timezone"),
                job_name=_mapping_optional_text(payload, "job_name"),
                custom_fields=_custom_fields(payload),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(_UNAVAILABLE) from exc
        now = self._clock()
        if (
            type(now) is not int
            or binding.intent_ref != intent_ref
            or not hmac.compare_digest(binding.requester_digest, requester_digest)
            or binding.environment_ref != environment_ref
            or binding.scope_ref != scope_ref
            or binding.expires_at <= now
        ):
            raise ValueError(_UNAVAILABLE)
        return SecretRequestCreatePreparedIntent(binding, request)

    def _load(self) -> Mapping[str, object]:
        content = bytearray()
        try:
            descriptor = os.open(
                self._path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or not 0 < metadata.st_size <= _MAX_BINDING_BYTES
                ):
                    raise OSError
                content = bytearray(os.read(descriptor, _MAX_BINDING_BYTES + 1))
            finally:
                os.close(descriptor)
            value = json.loads(content)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(content)
        if not isinstance(value, Mapping) or not all(
            isinstance(key, str) for key in value
        ):
            raise ValueError(_UNAVAILABLE)
        return value


class OwnerOnlySecretRequestCreateDispatchClaim:
    """Create one durable, exact-intent claim immediately before the POST."""

    __slots__ = ("_claimed_intent_hmac", "_hmac_key", "_path")

    def __init__(self, path: Path, hmac_key: bytes) -> None:
        self._path = Path(path)
        if (
            not self._path.is_absolute()
            or self._path.name in {"", ".", ".."}
            or type(hmac_key) is not bytes
            or len(hmac_key) < _MIN_HMAC_KEY_BYTES
        ):
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE)
        self._hmac_key = hmac_key
        self._claimed_intent_hmac: str | None = None

    def assert_unconsumed(self) -> None:
        """Reject retained claims before credentials; atomic claim still arbitrates races."""
        parent: int | None = None
        try:
            parent = self._open_owner_parent()
            try:
                os.stat(self._path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise OSError
        except OSError:
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE) from None
        finally:
            if parent is not None:
                os.close(parent)

    def claim(
        self,
        body: memoryview,
        *,
        binding: SecretRequestCreateBinding,
    ) -> None:
        """Atomically reserve this exact identity, scope, and request body once."""

        if not isinstance(body, memoryview) or not isinstance(
            binding, SecretRequestCreateBinding
        ):
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE)
        parent_descriptor: int | None = None
        try:
            parent_descriptor = os.open(
                self._path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            parent = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) & 0o077
            ):
                raise OSError
            intent_hmac = self._intent_hmac(body, binding)
            content = json.dumps(
                {
                    "contract": _DISPATCH_CLAIM_CONTRACT,
                    "dispatch_attempted": True,
                    "intent_binding_hmac": intent_hmac,
                    "retry_allowed": False,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii") + b"\n"
            descriptor = os.open(
                self._path.name,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            try:
                written = 0
                while written < len(content):
                    count = os.write(descriptor, content[written:])
                    if count <= 0:
                        raise OSError
                    written += count
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise OSError
            finally:
                os.close(descriptor)
            os.fsync(parent_descriptor)
            self._claimed_intent_hmac = intent_hmac
        except OSError:
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE) from None
        finally:
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    def finalize(
        self,
        *,
        terminal_outcome: str,
        failure_stage: str,
        http_status_class: str,
        post_http_status: int,
    ) -> None:
        """Atomically persist one value-minimized terminal diagnostic."""

        if (
            type(terminal_outcome) is not str
            or type(failure_stage) is not str
            or type(http_status_class) is not str
            or type(post_http_status) is not int
            or terminal_outcome not in _TERMINAL_OUTCOMES
            or failure_stage not in _FAILURE_STAGES
            or http_status_class not in _HTTP_STATUS_CLASSES
            or (post_http_status != 0 and not 100 <= post_http_status <= 599)
            or (
                http_status_class != (
                    "none"
                    if post_http_status in {0, 200}
                    else _http_status_class(post_http_status)
                )
            )
            or self._claimed_intent_hmac is None
            or (
                terminal_outcome == "bound"
                and (failure_stage != "none" or http_status_class != "none" or post_http_status != 200)
            )
            or (
                terminal_outcome == "reconciliation_required"
                and failure_stage == "none"
            )
        ):
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE)

        parent_descriptor: int | None = None
        temporary_created = False
        temporary_name = f".{self._path.name}.terminal"
        try:
            parent_descriptor = self._open_owner_parent()
            current = self._read_initial_claim(
                parent_descriptor, allow_bound=(terminal_outcome == "reconciliation_required"
                                               and failure_stage == "invocation_witness"),
            )
            intent_hmac = current.get("intent_binding_hmac")
            if (
                type(intent_hmac) is not str
                or not hmac.compare_digest(intent_hmac, self._claimed_intent_hmac)
            ):
                raise OSError
            content = json.dumps(
                {
                    **current,
                    "failure_stage": failure_stage,
                    "http_status_class": http_status_class,
                    "post_http_status": post_http_status,
                    "terminal_outcome": terminal_outcome,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii") + b"\n"
            descriptor = os.open(
                temporary_name,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            temporary_created = True
            try:
                self._write_all(descriptor, content)
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise OSError
            finally:
                os.close(descriptor)
            os.replace(
                temporary_name,
                self._path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            temporary_created = False
            os.fsync(parent_descriptor)
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE) from None
        finally:
            if temporary_created and parent_descriptor is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    def _open_owner_parent(self) -> int:
        descriptor = os.open(
            self._path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            os.close(descriptor)
            raise OSError
        return descriptor

    def _read_claim(self, parent_descriptor: int) -> dict[str, object]:
        descriptor = os.open(
            self._path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= _MAX_CLAIM_BYTES
            ):
                raise OSError
            content = os.read(descriptor, _MAX_CLAIM_BYTES + 1)
            if len(content) != metadata.st_size:
                raise OSError
        finally:
            os.close(descriptor)
        def members(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError
                result[key] = item
            return result
        value = json.loads(content, object_pairs_hook=members)
        if type(value) is not dict:
            raise OSError
        return value

    def _validate_bound_claim(self, value: dict[str, object]) -> None:
        expected = {
            "contract": _DISPATCH_CLAIM_CONTRACT,
            "dispatch_attempted": True,
            "intent_binding_hmac": self._claimed_intent_hmac,
            "retry_allowed": False,
            "terminal_outcome": "bound",
            "failure_stage": "none",
            "http_status_class": "none",
            "post_http_status": 200,
        }
        if self._claimed_intent_hmac is None or set(value) != set(expected):
            raise OSError
        for key, expected_value in expected.items():
            if type(value[key]) is not type(expected_value):
                raise OSError
            if key == "intent_binding_hmac":
                digest = value[key]
                if not isinstance(digest, str) or not hmac.compare_digest(digest, self._claimed_intent_hmac):
                    raise OSError
            elif value[key] != expected_value:
                raise OSError

    def bound_digest(self) -> str:
        """Hash only this invocation's exact durable successful terminal claim."""
        parent: int | None = None
        try:
            parent = self._open_owner_parent()
            value = self._read_claim(parent)
            self._validate_bound_claim(value)
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False).encode("ascii")
            return hashlib.sha256(canonical).hexdigest()
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            raise SecretRequestCreateDispatchClaimError(_UNAVAILABLE) from None
        finally:
            if parent is not None:
                os.close(parent)

    def _read_initial_claim(self, parent_descriptor: int, *, allow_bound: bool = False) -> dict[str, object]:
        value = self._read_claim(parent_descriptor)
        if allow_bound and "terminal_outcome" in value:
            self._validate_bound_claim(value)
            for key in ("terminal_outcome", "failure_stage", "http_status_class", "post_http_status"):
                value.pop(key)
        if (
            set(value) != {"contract", "dispatch_attempted", "intent_binding_hmac", "retry_allowed"}
            or value.get("contract") != _DISPATCH_CLAIM_CONTRACT
            or type(value.get("contract")) is not str
            or value.get("dispatch_attempted") is not True
            or value.get("retry_allowed") is not False
            or type(value.get("intent_binding_hmac")) is not str
        ):
            raise OSError
        return value

    @staticmethod
    def _write_all(descriptor: int, content: bytes) -> None:
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            if count <= 0:
                raise OSError
            written += count

    def _intent_hmac(
        self,
        body: memoryview,
        binding: SecretRequestCreateBinding,
    ) -> str:
        digest = hmac.new(self._hmac_key, digestmod=hashlib.sha256)
        for value in (
            _DISPATCH_CLAIM_CONTRACT,
            binding.intent_ref,
            binding.requester_digest,
            binding.environment_ref,
            binding.scope_ref,
            str(binding.expires_at),
            binding.submission_mode,
        ):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
        return digest.hexdigest()


class SecretRequestCreateTransportOutcome(str, Enum):
    """Value-minimized terminal outcome for one local create attempt."""

    BOUND = "bound"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreateTransportResult:
    """Protected internal result; never expose it through an MCP response."""

    outcome: SecretRequestCreateTransportOutcome
    protected_record: SecretRequestCollectionRecord | None
    raw_values_returned: Literal[False] = False


class _DefaultInspector(Protocol):
    def inspect(self) -> SecretRequestDefaultEvidence: ...


class _ActorInspector(Protocol):
    def inspect(self, expected_requester: str) -> None: ...


class _CreatorCollection(Protocol):
    def snapshot(self) -> SecretRequestCreatorSnapshot: ...


class _DetailObserver(Protocol):
    def observe(
        self,
        request_id: int,
        *,
        expected_secret_id: int,
        expected_request_type: Literal["launcher", "job"] = "launcher",
    ) -> SecretRequestObservation: ...


class _HttpResponse(Protocol):
    status: int

    def close(self) -> None: ...


class _HttpsConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: memoryview,
        headers: dict[str, str],
    ) -> None: ...

    def getresponse(self) -> _HttpResponse: ...

    def close(self) -> None: ...


class FortiPamSecretRequestCreateHttpTransport:
    """Attempt one protected create and bind it without reading POST output."""

    __slots__ = (
        "_actor_inspector",
        "_binding_resolver",
        "_claim",
        "_collection",
        "_config",
        "_connection_factory",
        "_default_inspector",
        "_detail_observer",
        "_diagnostic_http_status_class",
        "_diagnostic_post_http_status",
        "_diagnostic_stage",
        "_dispatch_claimed",
        "_environment_ref",
        "_lock",
        "_result",
        "_scope_ref",
        "_session_finalizer",
        "_request_dispatcher",
        "_invocation_witness_sink",
        "_witness_clock",
    )

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        binding_resolver: OwnerOnlySecretRequestCreateBindingResolver,
        dispatch_claim: OwnerOnlySecretRequestCreateDispatchClaim,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        actor_inspector: _ActorInspector | None = None,
        connection_factory: Callable[..., _HttpsConnection] | None = None,
        default_inspector: _DefaultInspector | None = None,
        collection: _CreatorCollection | None = None,
        detail_observer: _DetailObserver | None = None,
        session_finalizer: Callable[[], bool] | None = None,
        request_dispatcher: Callable[[memoryview], int] | None = None,
        invocation_witness_sink: SecretRequestCreateInvocationWitnessSink | None = None,
        witness_clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            not isinstance(config, SecretMetadataHttpTransportConfig)
            or not isinstance(
                binding_resolver,
                OwnerOnlySecretRequestCreateBindingResolver,
            )
            or not isinstance(
                dispatch_claim,
                OwnerOnlySecretRequestCreateDispatchClaim,
            )
            or (witness_clock is not None and not callable(witness_clock))
            or (invocation_witness_sink is not None and (
                not callable(getattr(invocation_witness_sink, "assert_available", None))
                or not callable(getattr(invocation_witness_sink, "publish", None))))
            or (session_finalizer is not None and not callable(session_finalizer))
            or (request_dispatcher is not None and (
                not callable(request_dispatcher) or session_finalizer is None
                or actor_inspector is None or default_inspector is None
                or collection is None or detail_observer is None
            ))
        ):
            raise ValueError(_UNAVAILABLE)
        try:
            environment_ref = require_ref(
                authorized_environment_ref,
                "authorized_environment_ref",
            )
            scope_ref = require_ref(authorized_scope_ref, "authorized_scope_ref")
        except (TypeError, ValueError) as exc:
            raise ValueError(_UNAVAILABLE) from exc
        self._config = config
        self._binding_resolver = binding_resolver
        self._claim = dispatch_claim
        self._environment_ref = environment_ref
        self._scope_ref = scope_ref
        self._connection_factory = connection_factory
        self._session_finalizer = session_finalizer
        self._request_dispatcher = request_dispatcher
        self._invocation_witness_sink = invocation_witness_sink
        self._witness_clock = witness_clock or time.time
        self._actor_inspector = actor_inspector or FortiPamSecretRequestActorHttpTransport(
            config
        )
        self._default_inspector = (
            default_inspector or FortiPamSecretRequestDefaultHttpTransport(config)
        )
        self._collection = (
            collection or FortiPamSecretRequestCollectionHttpTransport(config)
        )
        self._detail_observer = detail_observer or FortiPamSecretRequestHttpTransport(
            config
        )
        self._diagnostic_http_status_class = "none"
        self._diagnostic_post_http_status = 0
        self._diagnostic_stage = "intent_resolution"
        self._dispatch_claimed = False
        self._lock = Lock()
        self._result: SecretRequestCreateTransportResult | None = None

    def create(
        self,
        intent_ref: str,
        *,
        principal: V4PlanningPrincipal,
    ) -> SecretRequestCreateTransportResult:
        """Run at most one attempt; terminal replay returns the stored result."""

        with self._lock:
            if self._result is not None:
                return self._result
            self._result = SecretRequestCreateTransportResult(
                SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED,
                None,
            )
            finished: float | None = None
            try:
                started = self._witness_clock() if self._invocation_witness_sink is not None else 0.0
                self._diagnostic_http_status_class = "none"
                self._diagnostic_post_http_status = 0
                self._diagnostic_stage = "intent_resolution"
                if not isinstance(principal, V4PlanningPrincipal):
                    raise RuntimeError(_UNAVAILABLE)
                prepared = self._binding_resolver.resolve(
                    intent_ref=require_ref(intent_ref, "intent_ref"),
                    requester_digest=principal.requester.digest,
                    environment_ref=self._environment_ref,
                    scope_ref=self._scope_ref,
                )
                binding = prepared.binding
                request = prepared.request
                self._diagnostic_stage = "dispatch_claim_preflight"
                self._claim.assert_unconsumed()
                if self._invocation_witness_sink is not None:
                    self._diagnostic_stage = "invocation_witness"
                    self._invocation_witness_sink.assert_available()
                self._diagnostic_stage = "api_actor_preflight"
                self._actor_inspector.inspect(request.requester)
                self._diagnostic_stage = "default_read"
                evidence = self._default_inspector.inspect()
                self._diagnostic_stage = "creator_snapshot_before"
                before = self._collection.snapshot()
                self._claim_and_post_once(request, evidence, binding)
                # FortiPAM can acknowledge POST before the new record appears
                # in its creator view. Repeat only the bounded read; never POST.
                for attempt in range(40):
                    self._diagnostic_stage = "creator_snapshot_after"
                    try:
                        after = self._collection.snapshot()
                        self._diagnostic_stage = "delta_bind"
                        record = bind_new_secret_request(
                            before,
                            after,
                            expected_secret_id=request.secret_id,
                            expected_request_type=request.request_type,
                        )
                        break
                    except SecretRequestCollectionHttpTransportError:
                        if attempt == 39:
                            raise
                        time.sleep(0.5)
                self._diagnostic_stage = "detail_read"
                observation = self._detail_observer.observe(
                    record.request_id,
                    expected_secret_id=request.secret_id,
                    expected_request_type=request.request_type,
                )
                if (
                    observation.request_exists is not True
                    or observation.request_type != request.request_type
                    or observation.raw_values_returned is not False
                ):
                    raise RuntimeError(_UNAVAILABLE)
                if self._invocation_witness_sink is not None:
                    self._diagnostic_stage = "invocation_witness"
                    finished = self._witness_clock()
                self._result = SecretRequestCreateTransportResult(
                    SecretRequestCreateTransportOutcome.BOUND,
                    record,
                )
            except Exception:
                # Never log exception text, response bodies, headers, request
                # values, selectors, identifiers, or credentials.
                logging.getLogger(__name__).warning(
                    "Secret request create failed: stage=%s http_status_class=%s",
                    self._diagnostic_stage,
                    self._diagnostic_http_status_class,
                )
            # A cookie-session candidate must prove logout before its durable
            # result can become bound. The finalizer is private composition,
            # never a caller-supplied callback, and must tolerate no login.
            if self._session_finalizer is not None:
                try:
                    if self._session_finalizer() is not True:
                        raise RuntimeError(_UNAVAILABLE)
                except Exception:
                    self._diagnostic_stage = "requester_session_cleanup"
                    self._result = SecretRequestCreateTransportResult(
                        SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED,
                        None,
                    )
            if self._dispatch_claimed:
                failure_stage = (
                    "none"
                    if self._result.outcome is SecretRequestCreateTransportOutcome.BOUND
                    else self._diagnostic_stage
                )
                try:
                    self._claim.finalize(
                        terminal_outcome=self._result.outcome.value,
                        failure_stage=failure_stage,
                        http_status_class=self._diagnostic_http_status_class,
                        post_http_status=self._diagnostic_post_http_status,
                    )
                except SecretRequestCreateDispatchClaimError:
                    self._result = SecretRequestCreateTransportResult(
                        SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED,
                        None,
                    )
                    logging.getLogger(__name__).warning(
                        "Secret request create terminal diagnostic persistence failed"
                    )
            if (self._result.outcome is SecretRequestCreateTransportOutcome.BOUND
                    and self._invocation_witness_sink is not None):
                try:
                    if finished is None:
                        raise RuntimeError(_UNAVAILABLE)
                    witness = SecretRequestCreateInvocationWitness(
                        binding.intent_ref, principal.requester.digest,
                        principal.transport_namespace_digest, binding.fortipam_requester,
                        binding.environment_ref, binding.scope_ref, record,
                        started, finished, self._claim.bound_digest(),
                    )
                    self._invocation_witness_sink.publish(witness)
                except Exception:
                    self._result = SecretRequestCreateTransportResult(
                        SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED, None,
                    )
                    try:
                        self._claim.finalize(
                            terminal_outcome="reconciliation_required",
                            failure_stage="invocation_witness",
                            http_status_class=self._diagnostic_http_status_class,
                            post_http_status=self._diagnostic_post_http_status,
                        )
                    except SecretRequestCreateDispatchClaimError:
                        pass
                    # Both witness and durable terminal claim are required by
                    # consumers; a partial publication never establishes trust.
            return self._result

    def _claim_and_post_once(
        self,
        request: SecretRequestCreateInput,
        evidence: SecretRequestDefaultEvidence,
        binding: SecretRequestCreateBinding,
    ) -> None:
        body = bytearray()
        body_view: memoryview | None = None
        connection: _HttpsConnection | None = None
        response: _HttpResponse | None = None
        try:
            body = bytearray(
                json.dumps(
                    request.body(evidence),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            parsed = urlsplit(self._config.base_url)
            if parsed.hostname is None:
                raise ValueError(_UNAVAILABLE)
            body_view = memoryview(body).toreadonly()
            self._diagnostic_stage = "dispatch_claim"
            self._claim.claim(body_view, binding=binding)
            self._dispatch_claimed = True
            self._diagnostic_stage = "post"
            if self._request_dispatcher is not None:
                status = self._request_dispatcher(body_view)
                if type(status) is not int or not 100 <= status <= 599:
                    raise RuntimeError(_UNAVAILABLE)
                self._diagnostic_post_http_status = status
                if status != 200:
                    self._diagnostic_http_status_class = _http_status_class(status)
                    raise RuntimeError(_UNAVAILABLE)
                return
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                REQUEST_CREATE_METHOD,
                f"{REQUEST_CREATE_PATH}?{REQUEST_CREATE_POST_QUERY}",
                body_view,
                {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "fortipam-mcp-v4-secret-request-create/1",
                },
            )
            response = connection.getresponse()
            self._diagnostic_post_http_status = int(response.status)
            # Never read the body: success and error responses are not a
            # source-backed binding and may echo protected request values.
            if int(response.status) != 200:
                self._diagnostic_http_status_class = _http_status_class(
                    int(response.status)
                )
                raise RuntimeError(_UNAVAILABLE)
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if body_view is not None:
                body_view.release()
            _zeroize_mutable(body)
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _http_status_class(status: int) -> str:
    if 400 <= status <= 499:
        return "http_4xx"
    if 500 <= status <= 599:
        return "http_5xx"
    return "http_other"


def _mapping_text(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if type(item) is not str:
        raise ValueError(_UNAVAILABLE)
    return item


def _mapping_optional_text(
    value: Mapping[str, object],
    key: str,
) -> str | None:
    item = value.get(key)
    if item is not None and type(item) is not str:
        raise ValueError(_UNAVAILABLE)
    return item


def _mapping_int(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if type(item) is not int:
        raise ValueError(_UNAVAILABLE)
    return item


def _request_type(value: Mapping[str, object]) -> Literal["launcher", "job"]:
    item = value.get("request_type")
    if item not in {"launcher", "job"}:
        raise ValueError(_UNAVAILABLE)
    return "launcher" if item == "launcher" else "job"


def _start_after_approve(
    value: Mapping[str, object],
) -> Literal["enable", "disable"]:
    item = value.get("start_after_approve")
    if item not in {"enable", "disable"}:
        raise ValueError(_UNAVAILABLE)
    return "enable" if item == "enable" else "disable"


def _custom_fields(
    value: Mapping[str, object],
) -> tuple[SecretRequestCustomField, ...]:
    items = value.get("custom_fields")
    if type(items) is not list:
        raise ValueError(_UNAVAILABLE)
    result: list[SecretRequestCustomField] = []
    for item in items:
        if type(item) is not dict or set(item) != {"name", "value", "required"}:
            raise ValueError(_UNAVAILABLE)
        required = item.get("required")
        if type(required) is not bool:
            raise ValueError(_UNAVAILABLE)
        result.append(
            SecretRequestCustomField(
                name=_mapping_text(item, "name"),
                value=_mapping_text(item, "value"),
                required=required,
            )
        )
    return tuple(result)


def _same_requester_mode(
    value: Mapping[str, object],
) -> Literal["same_requester"]:
    if value.get("submission_mode") != "same_requester":
        raise ValueError(_UNAVAILABLE)
    return "same_requester"


__all__ = [
    "FortiPamSecretRequestCreateHttpTransport",
    "OwnerOnlySecretRequestCreateBindingResolver",
    "OwnerOnlySecretRequestCreateDispatchClaim",
    "REQUEST_CREATE_INTENT_CONTRACT",
    "REQUEST_CREATE_INTENT_VERSION",
    "SecretRequestCreateBinding",
    "SecretRequestCreatePreparedIntent",
    "SecretRequestCreateDispatchClaimError",
    "SecretRequestCreateTransportOutcome",
    "SecretRequestCreateTransportResult",
]
