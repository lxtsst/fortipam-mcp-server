"""Unregistered 7.0 candidate adapter for one new owner-only child Folder."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import hmac
import hashlib
import json
import re
import time
from typing import Protocol

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4AdapterFailure, M4ExecutionPlan, canonical_digest
from .folder_http_transport import _isolated_child_body


ACTION_ID = "folder-create"
ACTION_VERSION = "3.3.0"
ADAPTER_REF = "fortipam-700-build29-isolated-child-folder-candidate"
RDP_POLICY_ADAPTER_REF = "fortipam-700-build29-initial-rdp-policy-folder-candidate-v1"
RDP_POLICY_ACTION_VERSION = "3.4.0"
_UNAVAILABLE = "The isolated Folder candidate is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class InitialRdpPolicyBinding:
    """One existing complete Policy; this is neither ownership nor a writer."""
    name: str
    configuration_digest: str
    serial_digest: str

    def __post_init__(self) -> None:
        if (type(self.name) is not str or re.fullmatch(
                r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}", self.name) is None
            or any(type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for value in (self.configuration_digest, self.serial_digest))):
            raise ValueError(_UNAVAILABLE)


def initial_rdp_policy_child_body(name: str, parent_folder_id: int, owner_name: str,
                                  policy: InitialRdpPolicyBinding) -> dict[str, object]:
    if type(policy) is not InitialRdpPolicyBinding:
        raise ValueError(_UNAVAILABLE)
    policy.__post_init__()
    body = _isolated_child_body(name, parent_folder_id, owner_name)
    body.update({"inherit-policy": "disable", "secret-policy": policy.name})
    # This explicit native relation is qualified independently of inherited v3.3.
    users = body["user-permission"]
    assert isinstance(users, list) and isinstance(users[0], dict)
    users[0]["allowed-launcher-type"] = "all"
    return body


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderBinding:
    name: str
    parent_folder_id: int
    owner_name: str
    parent_digest: str
    empty_inactive_policy: bool = field(default=False, kw_only=True)
    initial_rdp_policy: InitialRdpPolicyBinding | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if type(self.empty_inactive_policy) is not bool:
            raise ValueError(_UNAVAILABLE)
        if self.initial_rdp_policy is not None:
            if type(self.initial_rdp_policy) is not InitialRdpPolicyBinding or self.empty_inactive_policy:
                raise ValueError(_UNAVAILABLE)
            self.initial_rdp_policy.__post_init__()
        _isolated_child_body(self.name, self.parent_folder_id, self.owner_name,
                             empty_inactive_policy=self.empty_inactive_policy)
        if len(self.parent_digest) != 64 or any(c not in "0123456789abcdef" for c in self.parent_digest):
            raise ValueError(_UNAVAILABLE)

    @property
    def parameters_digest(self) -> str:
        body = _isolated_child_body(self.name, self.parent_folder_id, self.owner_name,
                                    empty_inactive_policy=self.empty_inactive_policy)
        if self.initial_rdp_policy is not None:
            p = self.initial_rdp_policy
            return canonical_digest({"contract": self.adapter_ref,
                "body": initial_rdp_policy_child_body(self.name, self.parent_folder_id, self.owner_name, p),
                "parent_digest": self.parent_digest, "initial_policy": {
                    "name": p.name, "configuration_digest": p.configuration_digest,
                    "serial_digest": p.serial_digest}})
        if self.empty_inactive_policy:
            # M2 canonical values exclude empty strings. Bind the exact fixed
            # encoded native body, retaining the legacy digest path by default.
            body_digest = hashlib.sha256(json.dumps(body, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
            return canonical_digest({"contract": ADAPTER_REF, "body_digest": body_digest,
                                     "parent_digest": self.parent_digest})
        return canonical_digest({"contract": ADAPTER_REF, "body": body, "parent_digest": self.parent_digest})

    def state_digest(self, *, exists: bool) -> str:
        return canonical_digest({"contract": self.adapter_ref, "parameters_digest": self.parameters_digest,
                                 "exists": exists, "owner_only": exists})

    @property
    def adapter_ref(self) -> str:
        return ADAPTER_REF if self.initial_rdp_policy is None else RDP_POLICY_ADAPTER_REF

    @property
    def action_version(self) -> str:
        return ACTION_VERSION if self.initial_rdp_policy is None else RDP_POLICY_ACTION_VERSION


class IsolatedFolderTransport(Protocol):
    """Private fixed reads; implementations must never return raw data to MCP."""
    def read_product_version_and_build(self) -> tuple[str, int]: ...
    def read_parent_digest(self, parent_folder_id: int) -> str: ...
    def owner_is_available(self, owner_name: str) -> bool: ...
    def find_child_ids(self, name: str, parent_folder_id: int) -> tuple[int, ...]: ...
    def create_isolated_child(self, *, name: str, parent_folder_id: int, owner_name: str,
                              empty_inactive_policy: bool = False,
                              before_dispatch: Callable[[], None] | None = None) -> dict[str, object]: ...
    def verify_isolated_child(self, folder_id: int, *, name: str, parent_folder_id: int, owner_name: str,
                              empty_inactive_policy: bool = False) -> bool: ...


class IsolatedFolderM4Adapter:
    """Use the existing authorization/idempotency kernel; no standalone dispatch API."""
    def __init__(self, plan: M4ExecutionPlan, binding: IsolatedFolderBinding,
                 transport: IsolatedFolderTransport, *,
                 clock: Callable[[], int] | None = None, expected_serial: str | None = None) -> None:
        self._plan, self._binding, self._transport = plan, binding, transport
        self._clock = clock if clock is not None else lambda: int(time.time())
        if expected_serial is not None and (
            type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
            or not callable(getattr(transport, "read_creation_device_serial", None))
        ):
            raise M4AdapterDenied(_UNAVAILABLE)
        self._expected_serial = expected_serial
        if binding.initial_rdp_policy is not None and (
            expected_serial is None or hashlib.sha256(expected_serial.encode("ascii")).hexdigest()
                != binding.initial_rdp_policy.serial_digest
            or any(not callable(getattr(transport, method, None)) for method in
                   ("initial_rdp_policy_matches", "create_initial_rdp_policy_child", "verify_initial_rdp_policy_child"))
        ):
            raise M4AdapterDenied(_UNAVAILABLE)
        if not callable(self._clock):
            raise M4AdapterDenied(_UNAVAILABLE)
        self._created_id: int | None = None
        self._postcondition_verified = False
        self._dispatched = False
        self._validate(plan)

    def _validate(self, plan: M4ExecutionPlan) -> None:
        b = self._binding
        if (plan != self._plan or plan.action_id != ACTION_ID or plan.action_version != b.action_version
            or plan.adapter_ref != b.adapter_ref or plan.parameters_digest != b.parameters_digest
            or plan.expected_current_digest != b.state_digest(exists=False)
            or plan.expected_state_digest != b.state_digest(exists=True)):
            raise M4AdapterDenied(_UNAVAILABLE)

    def _version_matches(self) -> bool:
        value = self._transport.read_product_version_and_build()
        return isinstance(value, tuple) and len(value) == 2 and value[0] == "7.0.0" and type(value[1]) is int and value[1] == 29

    def _preflight(self) -> None:
        b, t = self._binding, self._transport
        self._require_expected_serial()
        if (not self._version_matches()
            or t.read_parent_digest(b.parent_folder_id) != b.parent_digest
            or t.owner_is_available(b.owner_name) is not True
            or t.find_child_ids(b.name, b.parent_folder_id) != ()):
            raise M4AdapterDenied(_UNAVAILABLE)
        self._require_initial_policy()

    def _require_initial_policy(self) -> None:
        policy = self._binding.initial_rdp_policy
        if policy is not None and getattr(self._transport, "initial_rdp_policy_matches")(policy) is not True:
            raise M4AdapterDenied(_UNAVAILABLE)

    def _require_expected_serial(self) -> None:
        if self._expected_serial is None:
            return
        try:
            actual = getattr(self._transport, "read_creation_device_serial")()
            if type(actual) is not str or not hmac.compare_digest(actual, self._expected_serial):
                raise ValueError
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        try:
            self._preflight()
            return self._binding.state_digest(exists=False)
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._validate(plan)
        if self._dispatched:
            raise M4AdapterDenied(_UNAVAILABLE)
        # Recheck immediately before POST, including changes after read_current.
        self.read_current(plan)

        def require_active_plan() -> None:
            self._require_expected_serial()
            self._require_initial_policy()
            now = self._clock()
            if type(now) is not int or now < 0 or now >= plan.expires_at:
                raise M4AdapterDenied(_UNAVAILABLE)

        require_active_plan()
        self._dispatched = True
        b = self._binding
        try:
            if b.initial_rdp_policy is not None:
                response = getattr(self._transport, "create_initial_rdp_policy_child")(
                    name=b.name, parent_folder_id=b.parent_folder_id, owner_name=b.owner_name,
                    policy=b.initial_rdp_policy, before_dispatch=require_active_plan)
            elif b.empty_inactive_policy:
                response = self._transport.create_isolated_child(
                    name=b.name, parent_folder_id=b.parent_folder_id, owner_name=b.owner_name,
                    before_dispatch=require_active_plan, empty_inactive_policy=True)
            else:
                response = self._transport.create_isolated_child(
                    name=b.name, parent_folder_id=b.parent_folder_id, owner_name=b.owner_name,
                    before_dispatch=require_active_plan)
            value = response.get("mkey")
            if response.get("http_status") != 200 or type(value) is not int or value <= 0:
                raise ValueError
            self._created_id = value
        except M4AdapterDenied:
            raise
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        self._postcondition_verified = False
        b, t = self._binding, self._transport
        try:
            if (self._created_id is None or not self._version_matches()
                or t.read_parent_digest(b.parent_folder_id) != b.parent_digest
                or t.owner_is_available(b.owner_name) is not True
                or t.find_child_ids(b.name, b.parent_folder_id) != (self._created_id,)):
                raise ValueError
            self._require_initial_policy()
            if b.initial_rdp_policy is not None:
                verified = getattr(t, "verify_initial_rdp_policy_child")(
                    self._created_id, name=b.name, parent_folder_id=b.parent_folder_id,
                    owner_name=b.owner_name, policy=b.initial_rdp_policy)
            elif b.empty_inactive_policy:
                verified = t.verify_isolated_child(self._created_id, name=b.name,
                    parent_folder_id=b.parent_folder_id, owner_name=b.owner_name, empty_inactive_policy=True)
            else:
                verified = t.verify_isolated_child(self._created_id, name=b.name,
                    parent_folder_id=b.parent_folder_id, owner_name=b.owner_name)
            if verified is not True:
                raise ValueError
            self._postcondition_verified = True
            return b.state_digest(exists=True)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None

    @property
    def verified_created_id(self) -> int:
        """Private handoff available only after this instance's exact postcondition."""
        if not self._postcondition_verified or self._created_id is None:
            raise M4AdapterDenied(_UNAVAILABLE)
        return self._created_id
