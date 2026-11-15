"""One-use BP014 disabled-scan Discovery create and readback transport.

This fixed transport has no MCP registration or execution Gate. It can only
submit a disabled account-only body, then reconcile the
exact name through a minimized detail GET. It never starts a scan or imports
results. A consumed POST is never retried by this object.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING, Literal
from urllib.parse import quote

import httpx

from .discovery_entry_create_contract import (
    DISCOVERY_CREATE_PATH,
    DisabledAdDiscoveryCreateInput,
    DisabledUnixDiscoveryCreateInput,
)
from .discovery_entry_http_transport import (
    DiscoveryEntryHttpTransportError,
    inspect_discovery_entry_detail,
)
from .discovery_entry_projection import DiscoveryEntryReadback, DiscoverySourceType
from .secret_create_191_private_adapter import SecretCreate700DomainBinding
from .secret_metadata_http_transport import (
    DomainSecretMetadataInspection,
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)

if TYPE_CHECKING:
    from .domain_secret_projection_reader import DomainSecretReadTransport
    from .discovery_source_create_custody import DiscoverySourceCreateCustody


_UNAVAILABLE = "FortiPAM Discovery create transport is unavailable."
_DISPOSABLE_NAME = re.compile(r"\Abp014-discovery-(?:ad|unix)-disabled-[0-9]{8}-r[0-9]+\Z")
_DELETE_PATH = "/api/v2/cmdb/secret/discovery/{name}?vdom=root"
DiscoveryCreateInput = DisabledAdDiscoveryCreateInput | DisabledUnixDiscoveryCreateInput


def _expected_source_type(request: DiscoveryCreateInput) -> DiscoverySourceType:
    if type(request) is DisabledAdDiscoveryCreateInput:
        if not request.source_name.startswith("bp014-discovery-ad-disabled-"):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        return "Active-directory"
    if type(request) is DisabledUnixDiscoveryCreateInput:
        if not request.source_name.startswith("bp014-discovery-unix-disabled-"):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        return "Unix-like"
    raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)


class DiscoveryEntryCreateHttpTransportError(RuntimeError):
    """Stable failure with no source name, credential reference, or response."""


def _ad_credential_dependency_digest(
    request: DisabledAdDiscoveryCreateInput,
    binding: SecretCreate700DomainBinding,
) -> str:
    """Bind the fixed AD source to all private Domain intent selectors."""
    try:
        if (
            type(request) is not DisabledAdDiscoveryCreateInput
            or type(binding) is not SecretCreate700DomainBinding
            or _expected_source_type(request) != "Active-directory"
            or _DISPOSABLE_NAME.fullmatch(request.source_name) is None
        ):
            raise ValueError
        return hashlib.sha256(json.dumps({
            "contract": "fortipam-700-build29-ad-discovery-credential-dependency-v1",
            "source": request.body(),
            "domain_binding": asdict(binding),
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except Exception:
        raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None


def inspect_ad_credential_dependency(
    request: DisabledAdDiscoveryCreateInput,
    binding: SecretCreate700DomainBinding,
    transport: DomainSecretReadTransport,
) -> str:
    """Qualify one private AD binding through fixed metadata-only reads.

    This independent host entry does not authorize or dispatch Discovery. The
    Domain reader verifies the exact Target, Template, Folder and Secret, and
    erases unexpected credential fields before decoding. The opaque digest
    binds the source and its existing Secret ID to every Domain dependency.
    """

    try:
        digest = _ad_credential_dependency_digest(request, binding)
        if not callable(getattr(transport, "inspect_domain_account_projection", None)):
            raise ValueError
        result = transport.inspect_domain_account_projection(
            binding, expected_secret_id=request.discovery_secret_id,
        )
        if (
            type(result) is not DomainSecretMetadataInspection
            or any(type(value) is not bool for value in asdict(result).values())
            or not result.secret_exists
            or not result.metadata_verified
        ):
            raise ValueError
        return digest
    except Exception:
        raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryEntryCreateResult:
    """Categorical one-use result; an ambiguous POST still consumes the run."""

    exact_get_404_before_create: bool
    post_category: Literal["http_200", "ambiguous"]
    post_http_status: int | None
    readback: DiscoveryEntryReadback | None

    @property
    def verified(self) -> bool:
        return (
            self.exact_get_404_before_create
            and self.readback is not None
            and self.readback.create_readback_verified
        )

    def __repr__(self) -> str:
        return "<DiscoveryEntryCreateResult categorical>"


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryEntryCleanupResult:
    """Actor-scoped cleanup readback for the same verified fixture."""

    exact_source_verified_before_delete: bool
    delete_category: Literal["http_200", "ambiguous"]
    exact_get_404_after_delete: bool

    @property
    def verified(self) -> bool:
        return (
            self.exact_source_verified_before_delete
            and self.delete_category == "http_200"
            and self.exact_get_404_after_delete
        )

    def __repr__(self) -> str:
        return "<DiscoveryEntryCleanupResult categorical>"


class FortiPamDiscoveryEntryCreateHttpTransport:
    """Create once; optionally clean up only that verified disposable source."""

    __slots__ = ("_bound_request", "_bound_digest", "_cleanup_claim_path", "_config", "_create_attempted", "_delete_attempted", "_original_custody")

    def __init__(self, config: SecretMetadataHttpTransportConfig, *,
                 original_custody: DiscoverySourceCreateCustody | None = None) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        if original_custody is not None:
            from .discovery_source_create_custody import DiscoverySourceCreateCustody
            if type(original_custody) is not DiscoverySourceCreateCustody or not original_custody.matches_transport(config):
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._original_custody = original_custody
        self._create_attempted = False
        self._delete_attempted = False
        self._bound_request: DiscoveryCreateInput | None = None
        self._bound_digest: str | None = None
        self._cleanup_claim_path: Path | None = None

    @classmethod
    def for_reconciled_cleanup(
        cls, config: SecretMetadataHttpTransportConfig, request: DiscoveryCreateInput,
        *, accepted_digest: str, claim_path: Path,
    ) -> FortiPamDiscoveryEntryCreateHttpTransport:
        """Recover one trusted, reconciled creation binding after process exit.

        The private caller must establish the prior consumed creation and exact
        eligible fixture before binding its complete accepted record digest.
        This adds no caller-selectable MCP action. A durable claim is mandatory
        for this recovery path and is checked before any network access.
        """

        _expected_source_type(request)
        if (_DISPOSABLE_NAME.fullmatch(request.source_name) is None
                or not isinstance(accepted_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", accepted_digest) is None
                or not isinstance(claim_path, Path) or not claim_path.is_absolute()):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        transport = cls(config)
        transport._bound_request = request
        transport._bound_digest = accepted_digest
        transport._cleanup_claim_path = claim_path
        transport._create_attempted = True
        transport._require_unconsumed_cleanup()
        return transport

    def inspect_current(
        self, request: DiscoveryCreateInput
    ) -> DiscoveryEntryReadback | None:
        """Read one exact source without exposing its name or Secret ID."""

        source_type = _expected_source_type(request)
        try:
            return inspect_discovery_entry_detail(
                self._config,
                expected_name=request.source_name,
                expected_secret_id=request.discovery_secret_id,
                expected_source_type=source_type,
            )
        except DiscoveryEntryHttpTransportError:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None

    def inspect_credential_reference(
        self, request: DiscoveryCreateInput
    ) -> str:
        """Require this API actor to read the bound Secret and its Target."""

        _expected_source_type(request)
        if type(request) is DisabledAdDiscoveryCreateInput:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        secret = self._read_reference(
            f"/api/v2/cmdb/secret/database/{request.discovery_secret_id}"
            "?format=id%7Cname%7Ctarget"
        )
        rows = secret.get("results") if isinstance(secret, dict) else None
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        row = rows[0]
        target_name = row.get("target")
        if (
            type(row.get("id")) is not int
            or row.get("id") != request.discovery_secret_id
            or not isinstance(target_name, str)
            or not target_name
            or len(target_name) > 128
        ):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        target = self._read_reference(
            "/api/v2/cmdb/secret/target/"
            f"{quote(target_name, safe='')}?format=name"
        )
        target_rows = target.get("results") if isinstance(target, dict) else None
        if (
            not isinstance(target_rows, list)
            or len(target_rows) != 1
            or not isinstance(target_rows[0], dict)
            or target_rows[0].get("name") != target_name
        ):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        secret_name = row.get("name")
        if (
            not isinstance(secret_name, str) or not 0 < len(secret_name) <= 128
        ):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        return hashlib.sha256(json.dumps({
            "secret_id": request.discovery_secret_id,
            "secret_name": secret_name,
            "target_name": target_name,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _read_reference(self, path: str) -> object:
        content = bytearray()
        try:
            with httpx.Client(
                base_url=self._config.base_url,
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "GET", path,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                        "Cache-Control": "no-cache, no-store",
                    },
                ) as response:
                    if (
                        response.status_code != 200
                        or "json" not in response.headers.get("content-type", "").lower()
                    ):
                        raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
                    for chunk in response.iter_bytes():
                        if len(content) + len(chunk) > 16_384:
                            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
                        content.extend(chunk)
            if self._original_custody is None:
                payload = json.loads(content)
            else:
                if path.startswith("/api/v2/cmdb/secret/database/"):
                    from .secret_metadata_http_transport import _redact_json_field_values
                    _redact_json_field_values(content)
                    from . import secret_bulk_import_metadata as metadata
                    from .target_lifecycle_dependencies import _spans, _one
                    envelope = _spans(content)
                    fields = metadata._object_spans(content, *_one(content, envelope["results"]),
                        frozenset({"id", "name", "target"}))
                    if set(fields) != {"id", "name", "target"}:
                        raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
                    # Native Secret metadata can repeat unselected keys even
                    # with format. Validate their bytes without decoding them;
                    # every selected identity/envelope key remains unique.
                    payload = {key: metadata._scalar(content, envelope[key]) for key in (
                        "version", "build", "path", "name", "http_method", "http_status", "vdom", "serial", "status", "error", "limit_reached") if key in envelope}
                    payload["results"] = [{key: metadata._scalar(content, span) for key, span in fields.items()}]
                else:
                    payload = self._read_unique_reference(content)
                table = next((table for table in ("database", "target", "discovery")
                    if path.startswith("/api/v2/cmdb/secret/" + table + "/")), None)
                if table is None:
                    raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
                self._original_custody.check_read_device(payload, table=table)
            if (
                not isinstance(payload, dict)
                or payload.get("http_method") != "GET"
                or payload.get("http_status") != 200
            ):
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
            return payload
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(content)

    @staticmethod
    def _read_unique_reference(content: bytearray) -> object:
        from .discovery_review_http_transport import DiscoveryReviewHttpTransportError, _nonfinite, _unique_pairs
        try:
            return json.loads(content, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
        except DiscoveryReviewHttpTransportError:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None

    def create_and_readback(
        self, request: DiscoveryCreateInput, *,
        domain_binding: SecretCreate700DomainBinding | None = None,
        domain_read_transport: DomainSecretReadTransport | None = None,
        before_dispatch: Callable[[], None] | None = None,
    ) -> DiscoveryEntryCreateResult:
        """Reject visible names, dispatch once, then reconcile exact state."""

        source_type = _expected_source_type(request)
        if (
            _DISPOSABLE_NAME.fullmatch(request.source_name) is None
            or self._create_attempted
            or (before_dispatch is not None and not callable(before_dispatch))
        ):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        if type(request) is DisabledAdDiscoveryCreateInput:
            if (type(domain_binding) is not SecretCreate700DomainBinding
                    or not callable(getattr(domain_read_transport, "inspect_domain_account_projection", None))):
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        elif domain_binding is not None or domain_read_transport is not None:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        try:
            before = inspect_discovery_entry_detail(
                self._config, expected_name=request.source_name
            )
        except DiscoveryEntryHttpTransportError:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None
        if before is not None:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)

        if type(request) is DisabledAdDiscoveryCreateInput:
            assert domain_binding is not None and domain_read_transport is not None
            inspect_ad_credential_dependency(request, domain_binding, domain_read_transport)
        else:
            reference_digest = self.inspect_credential_reference(request)

        if before_dispatch is not None:
            try:
                before_dispatch()
            except Exception:
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None
        if self._original_custody is not None:
            if type(request) is not DisabledUnixDiscoveryCreateInput:
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
            self._original_custody.begin_original_send(request, self._config, reference_digest)
        self._create_attempted = True
        post_category, post_http_status = self._post_once(request)
        try:
            after = inspect_discovery_entry_detail(
                self._config,
                expected_name=request.source_name,
                expected_secret_id=request.discovery_secret_id,
                expected_source_type=source_type,
            )
        except DiscoveryEntryHttpTransportError:
            after = None
        result = DiscoveryEntryCreateResult(
            True, post_category, post_http_status, after
        )
        if result.verified and _DISPOSABLE_NAME.fullmatch(request.source_name):
            try:
                self._bound_digest = self._read_cleanup_digest(request, capture_original=True)
                self._bound_request = request
            except DiscoveryEntryCreateHttpTransportError:
                # Creation may be verified without authorizing compensation.
                self._bound_digest = None
        return result

    def cleanup_bound_disposable(
        self, *, before_dispatch: Callable[[], None] | None = None,
    ) -> DiscoveryEntryCleanupResult:
        """Delete only this object's verified fixture, with one dispatch."""

        if before_dispatch is not None and not callable(before_dispatch):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        self.inspect_bound_cleanup()
        request = self._bound_request
        assert request is not None
        if before_dispatch is not None:
            try:
                before_dispatch()
            except Exception:
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None
        self._reserve_cleanup_claim(request)
        self._delete_attempted = True
        delete_category = self._delete_once(request.source_name)
        try:
            absent = inspect_discovery_entry_detail(
                self._config, expected_name=request.source_name
            ) is None
        except DiscoveryEntryHttpTransportError:
            absent = False
        return DiscoveryEntryCleanupResult(True, delete_category, absent)

    def inspect_bound_cleanup(self) -> DiscoveryEntryReadback:
        """Verify the fixed eligible recovery without mutation or private output."""

        request = self._bound_request
        if request is None or self._bound_digest is None or self._delete_attempted:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        self._require_unconsumed_cleanup()
        try:
            current = inspect_discovery_entry_detail(
                self._config,
                expected_name=request.source_name,
                expected_secret_id=request.discovery_secret_id,
                expected_source_type=_expected_source_type(request),
            )
        except DiscoveryEntryHttpTransportError:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None
        if current is None or not current.create_readback_verified:
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        if not hmac.compare_digest(self._bound_digest, self._read_cleanup_digest(request)):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        return current

    def _require_unconsumed_cleanup(self) -> None:
        path = self._cleanup_claim_path
        if path is None:
            return
        try:
            parent = path.parent.lstat()
            if (path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                    or stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid()
                    or path.exists() or path.is_symlink()):
                raise ValueError
        except (OSError, ValueError):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None

    def _reserve_cleanup_claim(self, request: DiscoveryCreateInput) -> None:
        path = self._cleanup_claim_path
        if path is None:
            return
        self._require_unconsumed_cleanup()
        binding = hashlib.sha256(json.dumps({
            "source_name": request.source_name, "source_type": _expected_source_type(request),
            "secret_id": request.discovery_secret_id, "accepted_digest": self._bound_digest,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        try:
            parent_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parent = os.fstat(parent_descriptor)
                if stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid():
                    raise ValueError
                descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent_descriptor)
                with os.fdopen(descriptor, "w") as output:
                    json.dump({"contract": "fortipam_v4_discovery_cleanup_700_candidate_v1",
                               "dispatch": "consumed", "binding_digest": binding}, output)
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except (OSError, ValueError):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE) from None

    def _read_cleanup_digest(self, request: DiscoveryCreateInput, *, capture_original: bool = False) -> str:
        """Bind every field of the newly created fixture, without returning it."""

        payload = self._read_reference(_DELETE_PATH.format(name=quote(request.source_name, safe="")))
        if not isinstance(payload, dict) or any((
            payload.get("status") != "success",
            payload.get("path") != "secret",
            payload.get("name") != "discovery",
            payload.get("vdom") != "root",
            payload.get("version") != "v7.0.0",
            type(payload.get("build")) is not int,
            payload.get("build") != 29,
        )):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        rows = payload.get("results")
        if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
                or rows[0].get("name") != request.source_name):
            raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
        digest = hashlib.sha256(json.dumps(rows[0], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if capture_original and self._original_custody is not None:
            if type(request) is not DisabledUnixDiscoveryCreateInput:
                raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
            # Custody is extra provenance, never a change to the legacy create
            # or unscanned compensation predicates. Missing custody cannot
            # qualify a later scanned-Source recovery.
            try:
                self._original_custody.capture_original_state(request, payload)
            except ValueError:
                pass
        return digest

    def _post_once(
        self, request: DiscoveryCreateInput
    ) -> tuple[Literal["http_200", "ambiguous"], int | None]:
        content = bytearray()
        status: int | None = None
        captured = False
        try:
            with httpx.Client(
                base_url=self._config.base_url,
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    DISCOVERY_CREATE_PATH,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                        "Cache-Control": "no-cache, no-store",
                    },
                    json=request.body(),
                ) as response:
                    status = response.status_code
                    if self._original_custody is not None:
                        for chunk in response.iter_bytes():
                            if len(content) + len(chunk) > 16_384:
                                raise ValueError(_UNAVAILABLE)
                            content.extend(chunk)
                        captured = True
                        self._original_custody.capture_original_ack(content, http_status=status,
                            content_type=response.headers.get("content-type", ""))
                    return ("http_200" if status == 200 else "ambiguous", status)
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            if self._original_custody is not None and not captured:
                # A lost/malformed original response is recorded only from this
                # still-active producer, not reconstructed after process exit.
                try:
                    self._original_custody.capture_original_ack(bytearray(), http_status=status, content_type="")
                except ValueError:
                    pass
            return "ambiguous", status if self._original_custody is not None else None
        finally:
            _zeroize_mutable(content)

    def _delete_once(self, source_name: str) -> Literal["http_200", "ambiguous"]:
        path = _DELETE_PATH.format(name=quote(source_name, safe=""))
        content = bytearray()
        try:
            with httpx.Client(
                base_url=self._config.base_url,
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "DELETE",
                    path,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                        "Cache-Control": "no-cache, no-store",
                    },
                ) as response:
                    if (response.status_code != 200
                            or "json" not in response.headers.get("content-type", "").lower()):
                        return "ambiguous"
                    for chunk in response.iter_bytes():
                        if len(content) + len(chunk) > 16_384:
                            return "ambiguous"
                        content.extend(chunk)
            payload = json.loads(content)
            if not isinstance(payload, dict) or any((
                payload.get("status") != "success",
                payload.get("http_method") != "DELETE",
                payload.get("http_status") != 200,
                payload.get("path") != "secret",
                payload.get("name") != "discovery",
                payload.get("vdom") != "root",
                payload.get("version") != "v7.0.0",
                type(payload.get("build")) is not int,
                payload.get("build") != 29,
                "error" in payload and (type(payload["error"]) is not int or payload["error"] != 0),
            )):
                return "ambiguous"
            return "http_200"
        except (httpx.HTTPError, OSError, ValueError, TypeError):
            return "ambiguous"
        finally:
            _zeroize_mutable(content)
