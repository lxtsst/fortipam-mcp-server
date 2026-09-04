"""Local JSON-backed adapter for the V3.1 administrative-operation demo.

This adapter is intentionally not a FortiPAM client.  It implements a small,
fixed fixture state machine so the preview/confirmation/execution contracts can
be tested without network access, credentials, or a product device.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import tempfile
from threading import RLock
from typing import Any

from .controlled_operations import (
    OperationExecutionError,
    VerifiedActionRequest,
    VerifiedRollbackRequest,
)


ACTION_IDS = frozenset(
    {
        "create_public_folder",
        "create_target",
        "create_secret",
        "create_local_user",
        "assign_folder_access",
    }
)

_COLLECTIONS = {
    "create_public_folder": "public_folders",
    "create_target": "targets",
    "create_secret": "secrets",
    "create_local_user": "local_users",
    "assign_folder_access": "folder_access",
}
_DEFAULT_STATE: dict[str, dict[str, dict[str, object]]] = {
    collection: {} for collection in _COLLECTIONS.values()
}


class LabFixtureError(ValueError):
    """Raised when the local fixture cannot satisfy a closed contract."""


def state_digest(value: object) -> str:
    """Return a deterministic digest for a bounded, non-secret projection."""

    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LabAdminAdapter:
    """Fixed five-action adapter backed by a local JSON fixture.

    Secret material is accepted only as a transient non-empty marker through
    :meth:`stage_secret_material`; the fixture persists ``material_present``
    metadata and never persists or returns the material itself.
    """

    def __init__(self, state_path: Path | None = None) -> None:
        self.state_path = Path(state_path) if state_path is not None else None
        self._lock = RLock()
        self._pending_material: set[str] = set()
        self._state = self._load()

    def stage_secret_material(self, material_ref: str, value: str) -> None:
        """Stage a transient secret marker without retaining the secret value."""

        if not isinstance(material_ref, str) or not material_ref.strip():
            raise LabFixtureError("material_ref is required.")
        if not isinstance(value, str) or not value:
            raise LabFixtureError("secret material must be non-empty.")
        with self._lock:
            self._pending_material.add(material_ref)

    def discard_staged_material(self, material_ref: str) -> None:
        """Discard transient material state after a failed or completed attempt."""

        with self._lock:
            self._pending_material.discard(material_ref)

    def query_current(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        """Return a fixed, non-secret current-state projection."""

        self._validate_action(action_id)
        with self._lock:
            return self._projection(action_id, target_ref, parameters)

    def desired_state(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        """Return the expected non-secret projection for one fixed action."""

        self._validate_action(action_id)
        return self._desired_projection(action_id, target_ref, parameters)

    def read_current(
        self,
        request: VerifiedActionRequest | VerifiedRollbackRequest,
    ) -> str:
        action_id = (
            _external_action_id(_forward_action_id(request.contract.action_id))
            if request.contract.action_id.startswith("rollback-")
            else _external_action_id(request.contract.action_id)
        )
        projection = self.query_current(
            action_id,
            request.target_ref,
            request.parameters,
        )
        return state_digest(projection)

    def execute(self, request: VerifiedActionRequest) -> None:
        action_id = _external_action_id(request.contract.action_id)
        self._validate_action(action_id)
        with self._lock:
            parameters = dict(request.parameters)
            if action_id == "create_secret":
                material_ref = _string_parameter(parameters, "value_ref")
                if material_ref not in self._pending_material:
                    raise OperationExecutionError("Secret material was not staged.")
            collection = _COLLECTIONS[action_id]
            existing = self._state[collection].get(request.target_ref)
            desired = self._desired_projection(action_id, request.target_ref, parameters)
            if existing is not None:
                existing_projection = self._projection(action_id, request.target_ref, parameters)
                if existing_projection != desired:
                    raise OperationExecutionError("The fixture object conflicts with the requested state.")
                if action_id == "create_secret":
                    self._pending_material.discard(material_ref)
                return
            self._state[collection][request.target_ref] = self._stored_record(action_id, parameters)
            if action_id == "create_secret":
                self._pending_material.discard(material_ref)
            self._save()

    def verify_postcondition(self, request: VerifiedActionRequest) -> bool:
        action_id = _external_action_id(request.contract.action_id)
        projection = self.query_current(
            action_id,
            request.target_ref,
            request.parameters,
        )
        return projection == self._desired_projection(
            action_id,
            request.target_ref,
            request.parameters,
        )

    def rollback(self, request: VerifiedRollbackRequest) -> None:
        action_id = _external_action_id(_forward_action_id(request.contract.action_id))
        self._validate_action(action_id)
        with self._lock:
            self._state[_COLLECTIONS[action_id]].pop(request.target_ref, None)
            self._save()

    def verify_rollback_postcondition(self, request: VerifiedRollbackRequest) -> bool:
        action_id = _external_action_id(_forward_action_id(request.contract.action_id))
        with self._lock:
            return request.target_ref not in self._state[_COLLECTIONS[action_id]]

    def _projection(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        collection = _COLLECTIONS[action_id]
        record = self._state[collection].get(target_ref)
        if record is None:
            return {"action_id": action_id, "exists": False, "object_ref": target_ref}
        return {
            "action_id": action_id,
            "exists": True,
            "object_ref": target_ref,
            **dict(record),
        }

    @staticmethod
    def _desired_projection(
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        return {
            "action_id": action_id,
            "exists": True,
            "object_ref": target_ref,
            **LabAdminAdapter._public_record(action_id, parameters),
        }

    @staticmethod
    def _public_record(action_id: str, values: Mapping[str, object]) -> dict[str, object]:
        if action_id == "create_public_folder":
            return {
                "parent-folder": values["parent_folder_ref"],
                "folder-type": values["folder_type"],
                "secret-policy": values["vault_policy_ref"],
                "user-permission": values["user_permission"],
                "group-permission": values["group_permission"],
                "folder-permission": values["folder_permission"],
                "secret-permission": values["vault_permission"],
                "allowed-launcher-type": values["allowed_launcher_type"],
            }
        if action_id == "create_target":
            return {
                "class": values["target_class"],
                "template": values["template_ref"],
                "address": values["address_ref"],
                "gateway": values["gateway_ref"],
            }
        if action_id == "create_secret":
            return {
                "object-class": "secret/database",
                "name": values["name_ref"],
                "folder": values["folder_ref"],
                "template": values["template_ref"],
                "target": values["target_ref"],
                "material_status": "excluded",
                "dynamic-field": [
                    {
                        "name": values["field_name"],
                        "type": values["field_type"],
                        "material_status": "not_provided",
                        "desc": values["field_desc_ref"],
                    }
                ],
            }
        if action_id == "create_local_user":
            return {
                "system": "admin",
                "name": values["name_ref"],
                "status": values["status"],
                "accprofile": values["access_profile_ref"],
                "display-name": values["display_name_ref"],
                "comments": values["comments_ref"],
                "schedule": values["schedule_ref"],
                "two-factor": values["two_factor"],
            }
        if action_id == "assign_folder_access":
            return {
                "folder_ref": values["folder_ref"],
                "subject_ref": values["subject_ref"],
                "folder-permission": values["folder_permission"],
                "secret-permission": values["vault_permission"],
                "allowed-launcher-type": values["allowed_launcher_type"],
            }
        raise LabFixtureError("Unsupported fixture action.")

    @classmethod
    def _stored_record(
        cls,
        action_id: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        # This deliberately excludes confirmation_digest and material_ref.
        record = cls._public_record(action_id, parameters)
        return dict(record)

    def _load(self) -> dict[str, dict[str, dict[str, object]]]:
        if self.state_path is None or not self.state_path.exists():
            return {key: dict(value) for key, value in _DEFAULT_STATE.items()}
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LabFixtureError("The local fixture is unavailable or invalid.") from exc
        if not isinstance(payload, dict) or set(payload) != set(_DEFAULT_STATE):
            raise LabFixtureError("The local fixture schema is invalid.")
        result: dict[str, dict[str, dict[str, object]]] = {}
        for collection in _DEFAULT_STATE:
            raw = payload[collection]
            if not isinstance(raw, dict):
                raise LabFixtureError("The local fixture collection is invalid.")
            result[collection] = {}
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    raise LabFixtureError("The local fixture record is invalid.")
                result[collection][key] = dict(value)
        return result

    def _save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._state, sort_keys=True, separators=(",", ":"))
        descriptor, temporary = tempfile.mkstemp(
            prefix=".fortipam-lab-", suffix=".json", dir=self.state_path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    @staticmethod
    def _validate_action(action_id: str) -> None:
        if action_id not in ACTION_IDS:
            raise LabFixtureError("The fixture action is not allowlisted.")


def _string_parameter(parameters: Mapping[str, object], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value:
        raise OperationExecutionError("A required fixture parameter is invalid.")
    return value


def _forward_action_id(rollback_action_id: str) -> str:
    if not rollback_action_id.startswith("rollback-"):
        raise LabFixtureError("Rollback action is not allowlisted.")
    action_id = rollback_action_id.removeprefix("rollback-")
    if _external_action_id(action_id) not in ACTION_IDS:
        raise LabFixtureError("Rollback action is not allowlisted.")
    return action_id


def _external_action_id(action_id: str) -> str:
    external = action_id.replace("-", "_")
    if external not in ACTION_IDS:
        raise LabFixtureError("The fixture action is not allowlisted.")
    return external
