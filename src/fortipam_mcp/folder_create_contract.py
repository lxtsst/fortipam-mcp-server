"""Evidence-aware, documented-but-disabled Public Folder create contract.

The child-folder projection is derived from version-scoped provider evidence
and FortiPAM 1.9.1 documented defaults.  Root folders are a separate contract:
they cannot inherit policy or ZTNA, and a read-only GUI observation also shows
permission inheritance disabled and a default administrator owner grant.  The
exact permission-array API encoding is not public evidence, so root projection
fails closed unless a private adapter supplies an explicit evidence object.

This remains a pure local schema/projector module.  It has no HTTP client,
credentials, device adapter, MCP registration, or write capability.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol


class FolderCreateContractError(ValueError):
    """Raised when a documented folder contract value is unsafe or incomplete."""


class FolderCreateReadinessError(FolderCreateContractError):
    """Raised when evidence is insufficient to project a create body."""


class FolderPermissionEvidenceError(FolderCreateContractError):
    """Raised when private permission-encoding evidence is invalid."""


FolderType = Literal["public"]
FolderPlacement = Literal["root", "child"]

CREATE_METHOD = "POST"
CREATE_PATH = "/api/v2/cmdb/secret/folder"
COLLECTION_READ_METHOD = "GET"
COLLECTION_READ_PATH = "/api/v2/cmdb/secret/folder"
DETAIL_READ_METHOD = "GET"
DETAIL_READ_PATH = "/api/v2/cmdb/secret/folder/{id}"
DELETE_METHOD = "DELETE"
DELETE_PATH = "/api/v2/cmdb/secret/folder/{id}"
REQUEST_SCHEMA_REF = "folder-create-request-v2"
PROJECTION_REF = "folder-readback-projection-v1"

REQUEST_FIELDS = (
    "id",
    "name",
    "inherit-policy",
    "inherit-permission",
    "inherit-folder-ztna",
    "parent-folder",
    "user-permission",
    "group-permission",
)
ROOT_BASE_REQUEST_FIELDS = REQUEST_FIELDS[:-2]
_RESPONSE_FIELDS = REQUEST_FIELDS + ("folder-type", "secret-policy")
_MAX_NAME_LENGTH = 64
_MAX_PARENT_ID = 2_147_483_647
_MAX_POLICY_LENGTH = 128


def _bounded_text(value: object, field: str, maximum: int, *, slash_free: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FolderCreateContractError(f"{field} must be a bounded non-empty string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise FolderCreateContractError(f"{field} contains a control character.")
    if slash_free and ("/" in value or "\\" in value):
        raise FolderCreateContractError(f"{field} must not contain a path separator.")
    return value


@dataclass(frozen=True, slots=True)
class RootOwnerGrant:
    """Observed semantic grant required for a root-folder create projection."""

    principal_name: Literal["admin"] = "admin"
    folder_permission: Literal["Owner"] = "Owner"
    secret_permission: Literal["Owner"] = "Owner"
    allowed_services: Literal["All Services"] = "All Services"


def _validate_permission_entries(
    values: object,
    field: str,
    *,
    required_count: int | None,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(values, tuple):
        raise FolderPermissionEvidenceError(f"{field} must be an immutable tuple from a private adapter.")
    if required_count is not None and len(values) != required_count:
        raise FolderPermissionEvidenceError(f"{field} must contain exactly {required_count} entry.")
    if len(values) > 64:
        raise FolderPermissionEvidenceError(f"{field} exceeds the evidence bound.")
    for entry in values:
        if not isinstance(entry, Mapping) or not entry:
            raise FolderPermissionEvidenceError(f"{field} contains an invalid encoded entry.")
        if not all(isinstance(key, str) and key for key in entry):
            raise FolderPermissionEvidenceError(f"{field} contains an invalid encoded key.")
    return values


@dataclass(frozen=True, slots=True)
class RootPermissionEncodingEvidence:
    """Private-adapter attestation for the otherwise unknown root ACL schema.

    The public contract deliberately does not interpret or manufacture the
    encoded permission entry.  The adapter reference and evidence reference
    bind the opaque entry to a version-specific, privately validated schema.
    """

    adapter_ref: str
    evidence_ref: str
    request_schema_ref: str
    fortipam_version: Literal["1.9.1"]
    exact_schema_verified: Literal[True]
    owner_grant: RootOwnerGrant
    user_permission: tuple[Mapping[str, object], ...]
    group_permission: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        try:
            _bounded_text(self.adapter_ref, "adapter_ref", 128)
            _bounded_text(self.evidence_ref, "evidence_ref", 128)
            _bounded_text(self.request_schema_ref, "request_schema_ref", 128)
        except FolderCreateContractError as exc:
            raise FolderPermissionEvidenceError(str(exc)) from exc
        if self.fortipam_version != "1.9.1" or self.exact_schema_verified is not True:
            raise FolderPermissionEvidenceError(
                "Root permission encoding must be exactly verified for FortiPAM 1.9.1."
            )
        if self.owner_grant != RootOwnerGrant():
            raise FolderPermissionEvidenceError(
                "Root permission evidence must preserve admin Owner/Owner/All Services semantics."
            )
        _validate_permission_entries(self.user_permission, "user_permission", required_count=1)
        _validate_permission_entries(self.group_permission, "group_permission", required_count=0)


@dataclass(frozen=True, slots=True)
class FolderCreateReadiness:
    """Local body-projection readiness; never an execution authorization."""

    placement: FolderPlacement
    body_projection_ready: bool
    permission_encoding_required: bool
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FolderCreateRequest:
    """Strict request inputs with an explicit root/child placement."""

    name: str
    placement: FolderPlacement
    parent_folder_id: int | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.name, "name", _MAX_NAME_LENGTH, slash_free=True)
        if self.placement not in {"root", "child"}:
            raise FolderCreateContractError("placement must be root or child.")
        if self.placement == "root":
            if self.parent_folder_id is not None:
                raise FolderCreateContractError("A root folder must not declare a parent_folder_id.")
        else:
            if (
                type(self.parent_folder_id) is not int
                or self.parent_folder_id <= 0
                or self.parent_folder_id > _MAX_PARENT_ID
            ):
                raise FolderCreateContractError(
                    "A child parent_folder_id must be a positive signed int32 value."
                )

    @classmethod
    def root(cls, name: str) -> FolderCreateRequest:
        return cls(name=name, placement="root")

    @classmethod
    def child(
        cls,
        name: str,
        parent_folder_id: int,
    ) -> FolderCreateRequest:
        return cls(
            name=name,
            placement="child",
            parent_folder_id=parent_folder_id,
        )

    def readiness(
        self,
        permission_evidence: RootPermissionEncodingEvidence | None = None,
    ) -> FolderCreateReadiness:
        """Assess whether this module can safely project a local request body."""
        if self.placement == "child":
            blockers = () if permission_evidence is None else ("root-permission-evidence-on-child",)
            return FolderCreateReadiness(
                placement="child",
                body_projection_ready=not blockers,
                permission_encoding_required=False,
                blockers=blockers,
            )
        if permission_evidence is None:
            return FolderCreateReadiness(
                placement="root",
                body_projection_ready=False,
                permission_encoding_required=True,
                blockers=("exact-root-permission-array-schema-unverified",),
            )
        return FolderCreateReadiness(
            placement="root",
            body_projection_ready=True,
            permission_encoding_required=True,
            blockers=(),
        )

    def body(
        self,
        permission_evidence: RootPermissionEncodingEvidence | None = None,
    ) -> dict[str, object]:
        """Build a local body projection after scope-specific evidence checks."""
        readiness = self.readiness(permission_evidence)
        if not readiness.body_projection_ready:
            raise FolderCreateReadinessError(
                "Folder create body is not ready: " + ", ".join(readiness.blockers)
            )

        parent_id = 0 if self.placement == "root" else self.parent_folder_id
        body: dict[str, object] = {
            "id": 0,
            "name": self.name,
            "inherit-policy": "disable" if self.placement == "root" else "enable",
            "inherit-permission": "disable" if self.placement == "root" else "enable",
            "inherit-folder-ztna": "disable" if self.placement == "root" else "enable",
            "parent-folder": parent_id,
        }
        if self.placement == "child":
            body["user-permission"] = []
            body["group-permission"] = []
            return body

        if permission_evidence is None:  # Defensive narrowing after readiness.
            raise FolderCreateReadinessError("Root permission evidence is required.")
        body["user-permission"] = [dict(entry) for entry in permission_evidence.user_permission]
        # Empty arrays are intentionally not emitted for root folders.  This
        # bounded contract has no observed group grant, so group-permission is
        # omitted instead of guessing its encoding.
        return body


@dataclass(frozen=True, slots=True)
class FolderProjection:
    """Fixed value-free state used for current/readback comparison."""

    exists: bool
    object_id: int
    name: str
    parent_folder_id: int
    folder_type: str
    inherit_policy: str
    inherit_permission: str
    inherit_folder_ztna: str
    secret_policy: str
    user_permission_count: int
    group_permission_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "exists": self.exists,
            "id": self.object_id,
            "name": self.name,
            "parent-folder-id": self.parent_folder_id,
            "folder-type": self.folder_type,
            "inherit-policy": self.inherit_policy,
            "inherit-permission": self.inherit_permission,
            "inherit-folder-ztna": self.inherit_folder_ztna,
            "secret-policy": self.secret_policy,
            "user-permission-count": self.user_permission_count,
            "group-permission-count": self.group_permission_count,
        }


def project_folder_response(response: Mapping[str, object]) -> FolderProjection:
    """Project one sanitized response and reject unknown/raw response fields."""
    if not isinstance(response, Mapping):
        raise FolderCreateContractError("Folder response must be an object.")
    unknown = set(response) - set(_RESPONSE_FIELDS)
    missing = set(_RESPONSE_FIELDS) - set(response)
    if unknown or missing:
        raise FolderCreateContractError("Folder response shape is not the fixed projection contract.")
    object_id = response["id"]
    if type(object_id) is not int or object_id < 0:
        raise FolderCreateContractError("Folder response id is invalid.")
    name = _bounded_text(response["name"], "name", _MAX_NAME_LENGTH, slash_free=True)
    parent = response["parent-folder"]
    if type(parent) is not int or parent < 0 or parent > _MAX_PARENT_ID:
        raise FolderCreateContractError("Folder response parent-folder id is invalid.")
    folder_type = _bounded_text(response["folder-type"], "folder-type", 32, slash_free=True)
    if folder_type != "public":
        raise FolderCreateContractError("Folder response is not a Public Folder.")
    inherit_policy = _bounded_text(response["inherit-policy"], "inherit-policy", 16)
    inherit_permission = _bounded_text(response["inherit-permission"], "inherit-permission", 16)
    inherit_ztna = _bounded_text(response["inherit-folder-ztna"], "inherit-folder-ztna", 16)
    secret_policy = _bounded_text(response["secret-policy"], "secret-policy", _MAX_POLICY_LENGTH, slash_free=True)
    for field in ("inherit-policy", "inherit-permission", "inherit-folder-ztna"):
        if response[field] not in {"enable", "disable"}:
            raise FolderCreateContractError(f"{field} is outside the documented enum.")
    permission_values: dict[str, Sequence[object]] = {}
    for field in ("user-permission", "group-permission"):
        values = response[field]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
            raise FolderCreateContractError(f"{field} must be a bounded permission array.")
        if len(values) > 64:
            raise FolderCreateContractError(f"{field} exceeds the projection bound.")
        if not all(isinstance(entry, Mapping) and entry for entry in values):
            raise FolderCreateContractError(f"{field} contains an invalid permission entry.")
        permission_values[field] = values
    if parent == 0:
        if {inherit_policy, inherit_permission, inherit_ztna} != {"disable"}:
            raise FolderCreateContractError("A root folder cannot report inherited controls.")
        if not permission_values["user-permission"]:
            raise FolderCreateContractError("A root folder must report its owner permission entry.")
    return FolderProjection(
        exists=True,
        object_id=object_id,
        name=name,
        parent_folder_id=parent,
        folder_type=folder_type,
        inherit_policy=inherit_policy,
        inherit_permission=inherit_permission,
        inherit_folder_ztna=inherit_ztna,
        secret_policy=secret_policy,
        user_permission_count=len(permission_values["user-permission"]),
        group_permission_count=len(permission_values["group-permission"]),
    )


class FolderReadTransport(Protocol):
    """Read-only shape for a future fixed adapter; no HTTP is implemented."""

    def read_folder(self, folder_id: int) -> Mapping[str, object]: ...


class MockFolderReadTransport:
    """Deterministic test transport; it never contacts a product."""

    def __init__(self, response: Mapping[str, object]) -> None:
        self._response = dict(response)

    def read_folder(self, folder_id: int) -> Mapping[str, object]:
        del folder_id
        return dict(self._response)


__all__ = [
    "COLLECTION_READ_METHOD",
    "COLLECTION_READ_PATH",
    "CREATE_METHOD",
    "CREATE_PATH",
    "DELETE_METHOD",
    "DELETE_PATH",
    "DETAIL_READ_METHOD",
    "DETAIL_READ_PATH",
    "FolderCreateContractError",
    "FolderCreateReadiness",
    "FolderCreateReadinessError",
    "FolderCreateRequest",
    "FolderPermissionEvidenceError",
    "FolderPlacement",
    "FolderProjection",
    "FolderReadTransport",
    "MockFolderReadTransport",
    "PROJECTION_REF",
    "REQUEST_FIELDS",
    "REQUEST_SCHEMA_REF",
    "ROOT_BASE_REQUEST_FIELDS",
    "RootOwnerGrant",
    "RootPermissionEncodingEvidence",
    "project_folder_response",
]
