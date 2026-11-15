from dataclasses import replace
import json
from typing import Any, Callable

import pytest

from fortipam_mcp.secret_dlp_association_contract import (
    SecretDlpAssociationIdentity, SecretDlpAssociationInspection, SecretDlpAssociationReadback,
    fixed_log_only_sensor_profile, project_secret_dlp_metadata,
    qualify_secret_dlp_association_inspection,
)
from fortipam_mcp.secret_dlp_association_live_workflow import (
    SecretDlpAssociationLiveWorkflow, SecretDlpAssociationLiveWorkflowError,
)


REQUESTER = "b" * 64
SENSOR = "mcp-v4-dlp-sftp-audit-synthetic"
IDENTITY = SecretDlpAssociationIdentity(17, "mcp-v4-bp005-dlp-audit-synthetic", 9,
                                      "Unix Account (SSH Password)", "synthetic-target")


def inspection(*, associated: bool = False, metadata: str = "unchanged", actor: str = "a" * 64,
               opaque: str = "c" * 64, omit_inactive: bool = False) -> SecretDlpAssociationInspection:
    envelope: dict[str, Any] = {"version": "v7.0.0", "build": 29, "status": "OK", "http_method": "GET",
                               "http_status": 200, "path": "secret", "name": "database"}
    row = {"id": IDENTITY.id, "name": IDENTITY.name, "folder": IDENTITY.folder, "template": IDENTITY.template,
           "target": IDENTITY.target, "description": "Synthetic fixture", "proxy": "enable", "recording": "enable",
           "ssh-service-status": "up", "sftp-service-status": "up", "ssh-filter": "disable", "ssh-filter-profile": "",
           "dlp-status": "enable" if associated else "disable", "dlp-sensor": SENSOR if associated else "",
           "field": None, "unrelated-metadata": metadata}
    shape = [{"id": 1, "name": "Password", "type": "password"},
             {"id": 2, "name": "Username", "type": "username"}]
    projected = project_secret_dlp_metadata({**envelope, "results": row}, credential_shape=shape, opaque_field_digest=opaque)
    native: dict[str, Any] = dict(fixed_log_only_sensor_profile(sensor_name=SENSOR))
    native["q_origin_key"] = SENSOR
    native["filter"][0]["q_origin_key"] = 1
    if omit_inactive:
        del native["filter"][0]["file-size"]
        del native["filter"][0]["match-percentage"]
    return qualify_secret_dlp_association_inspection(
        projected, {**envelope, "path": "dlp", "name": "sensor", "results": native},
        identity=IDENTITY, sensor_name=SENSOR, actor_digest=actor, redacted_metadata_witness_digest="d" * 64,
    )


class Clock:
    def __init__(self) -> None:
        self.value = 1000

    def __call__(self) -> int:
        return self.value


class Transport:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.current = inspection()
        self.inspections = 0
        self.associations = 0
        self.restorations = 0
        self.failure: str | None = None
        self.expire_on_inspection = False

    def _inspect(self) -> SecretDlpAssociationInspection:
        self.inspections += 1
        if self.expire_on_inspection:
            self.clock.value += 601
        return self.current

    def inspect_association(self) -> SecretDlpAssociationInspection:
        return self._inspect()

    def inspect_owned_restore(self) -> SecretDlpAssociationInspection:
        return self._inspect()

    def associate_and_readback(self, expected_state_digest: str, *, expires_at: int,
                               clock: Callable[[], int]) -> SecretDlpAssociationReadback:
        return self._write(expected_state_digest, expires_at=expires_at, clock=clock, associated=True)

    def restore_and_readback(self, expected_state_digest: str, *, expires_at: int,
                             clock: Callable[[], int]) -> SecretDlpAssociationReadback:
        return self._write(expected_state_digest, expires_at=expires_at, clock=clock, associated=False)

    def _write(self, expected_state_digest: str, *, expires_at: int, clock: Callable[[], int],
               associated: bool) -> SecretDlpAssociationReadback:
        assert expected_state_digest == self.current.state_digest
        if self.failure == "private_read_expired":
            self.clock.value = expires_at
        if clock() >= expires_at:
            raise TimeoutError("synthetic-private-detail")
        if associated: self.associations += 1
        else: self.restorations += 1
        if self.failure == "ambiguous":
            raise TimeoutError("synthetic-private-detail")
        after = inspection(associated=associated, metadata="drift" if self.failure == "metadata" else "unchanged",
                           actor="e" * 64 if self.failure == "actor" else "a" * 64,
                           opaque="e" * 64 if self.failure == "opaque" else "c" * 64,
                           omit_inactive=self.failure == "sensor_shape")
        self.current = after
        if self.failure == "wrong_phase": after = inspection(associated=not associated)
        if self.failure == "unqualified_after": after = replace(after, native_sensor_json="{}")
        return SecretDlpAssociationReadback(self.failure != "ack", self.failure != "logout",
                                           self.failure != "fields", None if self.failure == "missing_after" else after)


def authorize(workflow: SecretDlpAssociationLiveWorkflow, *, restore: bool = False) -> tuple[dict[str, Any], str]:
    preview = (workflow.preview_restore if restore else workflow.preview_association)(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    return preview, str(confirmed["authorization_ref"])


def test_association_and_fresh_same_creator_restore_keep_all_selectors_private() -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    preview, authorization = authorize(workflow)
    associated = workflow.execute(authorization, requester_digest=REQUESTER)
    restore_preview, restore_auth = authorize(workflow, restore=True)
    restored = workflow.execute(restore_auth, requester_digest=REQUESTER)
    assert associated["outcome"] == restored["outcome"] == "succeeded"
    assert transport.associations == transport.restorations == 1
    assert "-associate-" in authorization and "-restore-" in restore_auth
    assert preview["preview_ref"] != restore_preview["preview_ref"]
    assert transport.current == inspection()
    public = json.dumps((preview, associated, restore_preview, restored))
    assert all(value not in public for value in (IDENTITY.name, IDENTITY.target, IDENTITY.template, SENSOR,
                                                "Password", "Username", "folder", "native_sensor_json"))
    assert workflow.execute(authorization, requester_digest=REQUESTER)["idempotent_replay"]
    assert workflow.execute(restore_auth, requester_digest=REQUESTER)["idempotent_replay"]
    assert transport.associations == transport.restorations == 1


def test_default_gate_and_confirmation_are_independent_required_boundaries() -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, clock=clock)
    preview, auth = authorize(workflow)
    with pytest.raises(SecretDlpAssociationLiveWorkflowError):
        workflow.execute(str(preview["preview_ref"]), requester_digest=REQUESTER)
    with pytest.raises(SecretDlpAssociationLiveWorkflowError):
        workflow.execute(auth, requester_digest=REQUESTER)
    assert transport.associations == 0


@pytest.mark.parametrize("failure", ("ambiguous", "ack", "logout", "fields", "missing_after",
    "metadata", "actor", "opaque", "sensor_shape", "wrong_phase", "unqualified_after", "private_read_expired"))
def test_uncertain_or_unpreserved_attempts_consume_refs_and_never_grant_restore(failure: str) -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    _, auth = authorize(workflow)
    transport.failure = failure
    result = workflow.execute(auth, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required" and result["device_write_may_have_occurred"]
    assert "synthetic-private-detail" not in json.dumps(result)
    assert workflow.execute(auth, requester_digest=REQUESTER)["idempotent_replay"]
    assert transport.associations == (0 if failure == "private_read_expired" else 1)
    for preview_method in (workflow.preview_association, workflow.preview_restore):
        with pytest.raises(SecretDlpAssociationLiveWorkflowError): preview_method(requester_digest=REQUESTER)


@pytest.mark.parametrize("stage", ("preview", "confirm", "execute"))
def test_expiry_after_fresh_inspection_never_dispatches(stage: str) -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    if stage == "preview":
        transport.expire_on_inspection = True
        with pytest.raises(SecretDlpAssociationLiveWorkflowError): workflow.preview_association(requester_digest=REQUESTER)
    else:
        preview = workflow.preview_association(requester_digest=REQUESTER)
        if stage == "confirm":
            transport.expire_on_inspection = True
            with pytest.raises(SecretDlpAssociationLiveWorkflowError):
                workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        else:
            confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
            transport.expire_on_inspection = True
            assert workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)["outcome"] == "not_executed"
    assert transport.associations == 0


@pytest.mark.parametrize("stage", ("confirm", "execute"))
@pytest.mark.parametrize("drift", ("actor", "metadata", "opaque", "sensor_shape"))
def test_fresh_qualified_state_drift_invalidates_without_write(stage: str, drift: str) -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    preview = workflow.preview_association(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER) if stage == "execute" else None
    transport.current = inspection(actor="e" * 64 if drift == "actor" else "a" * 64,
        metadata="drift" if drift == "metadata" else "unchanged", opaque="e" * 64 if drift == "opaque" else "c" * 64,
        omit_inactive=drift == "sensor_shape")
    if stage == "confirm":
        with pytest.raises(SecretDlpAssociationLiveWorkflowError):
            workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    else:
        assert confirmed is not None
        assert workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)["outcome"] == "not_executed"
    assert transport.associations == 0


def test_requester_and_instance_ownership_cannot_be_imported_or_rebound() -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    preview, auth = authorize(workflow)
    with pytest.raises(SecretDlpAssociationLiveWorkflowError):
        workflow.execute(auth, requester_digest="e" * 64)
    assert workflow.execute(auth, requester_digest=REQUESTER)["outcome"] == "succeeded"
    with pytest.raises(SecretDlpAssociationLiveWorkflowError): workflow.preview_restore(requester_digest="e" * 64)
    restarted = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    for action in (lambda: restarted.execute(auth, requester_digest=REQUESTER),
                   lambda: restarted.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER),
                   lambda: restarted.preview_restore(requester_digest=REQUESTER)):
        with pytest.raises(SecretDlpAssociationLiveWorkflowError): action()
    assert transport.associations == 1 and transport.restorations == 0


def test_multiple_authorizations_cannot_dispatch_a_second_association() -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    _, first = authorize(workflow)
    _, second = authorize(workflow)
    assert workflow.execute(first, requester_digest=REQUESTER)["outcome"] == "succeeded"
    assert workflow.execute(second, requester_digest=REQUESTER)["outcome"] == "not_executed"
    assert transport.associations == 1


def test_restore_requires_exact_fresh_owned_association_and_preserved_original_baseline() -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    with pytest.raises(SecretDlpAssociationLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)
    _, auth = authorize(workflow)
    assert workflow.execute(auth, requester_digest=REQUESTER)["outcome"] == "succeeded"
    transport.current = inspection(associated=True, metadata="drift")
    with pytest.raises(SecretDlpAssociationLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)
    assert transport.restorations == 0


@pytest.mark.parametrize("failure", ("ambiguous", "ack"))
def test_owned_restore_uncertainty_is_consumed_without_retry(failure: str) -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    _, association_auth = authorize(workflow)
    assert workflow.execute(association_auth, requester_digest=REQUESTER)["outcome"] == "succeeded"
    _, restore_auth = authorize(workflow, restore=True)
    transport.failure = failure
    assert workflow.execute(restore_auth, requester_digest=REQUESTER)["outcome"] == "reconciliation_required"
    assert workflow.execute(restore_auth, requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(SecretDlpAssociationLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)
    assert transport.associations == transport.restorations == 1


@pytest.mark.parametrize("stage", ("preview", "confirm", "execute"))
def test_every_fresh_boundary_requalifies_complete_native_sensor(stage: str) -> None:
    clock = Clock()
    transport = Transport(clock)
    workflow = SecretDlpAssociationLiveWorkflow(transport, execution_enabled=True, clock=clock)
    preview = workflow.preview_association(requester_digest=REQUESTER) if stage != "preview" else None
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER) if stage == "execute" and preview else None
    transport.current = replace(transport.current, native_sensor_json="{}")
    if stage == "execute":
        assert confirmed is not None
        assert workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)["outcome"] == "not_executed"
    else:
        with pytest.raises(SecretDlpAssociationLiveWorkflowError):
            if stage == "preview": workflow.preview_association(requester_digest=REQUESTER)
            else:
                assert preview is not None
                workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.associations == 0
