from __future__ import annotations

import pytest

from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataInspection,
    SecretMetadataReadback,
)
from fortipam_mcp.secret_metadata_live_workflow import (
    SecretMetadataLiveWorkflow,
    SecretMetadataLiveWorkflowError,
)


REQUESTER = "a" * 64
FOLDER_PATH = "Public/mcp-v4-folder-01"
SECRET_NAME = "mcp-v4-secret-metadata-01"
TEMPLATE = "Unix Account (SSH Password)"


class FakeSecretMetadataTransport:
    def __init__(self) -> None:
        self.secret_exists = False
        self.folder_exists = True
        self.template_exists = True
        self.create_calls: list[tuple[str, str, str]] = []
        self.readback = SecretMetadataReadback(True, True, True, True, False)

    def inspect(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataInspection:
        return SecretMetadataInspection(
            self.secret_exists,
            self.folder_exists,
            self.template_exists,
        )

    def create_and_readback(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataReadback:
        self.create_calls.append((folder_path, secret_name, template))
        self.secret_exists = True
        return self.readback


def _preview(workflow: SecretMetadataLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        folder_path=FOLDER_PATH,
        secret_name=SECRET_NAME,
        template=TEMPLATE,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_shows_requested_non_secret_metadata() -> None:
    preview = _preview(SecretMetadataLiveWorkflow(FakeSecretMetadataTransport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "requested_folder_path": FOLDER_PATH,
        "requested_secret_name": SECRET_NAME,
        "requested_template": TEMPLATE,
        "secret_exists": False,
        "folder_exists": True,
        "template_exists": True,
        "write_transport": "rest_api",
        "credential_material_attached": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_secret_metadata_without_credential_material_via_api",
        "folder_path": FOLDER_PATH,
        "secret_name": SECRET_NAME,
        "template": TEMPLATE,
        "credential_material_supplied": False,
        "credential_material_returned": False,
    }
    assert preview["Expected State"] == {
        "secret_exists": True,
        "secret_name_matches": True,
        "folder_matches": True,
        "template_matches": True,
        "inherit_permission_matches": True,
        "credential_material_attached": False,
    }
    assert FOLDER_PATH in str(preview)
    assert SECRET_NAME in str(preview)
    assert TEMPLATE in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_runs_one_metadata_only_create() -> None:
    transport = FakeSecretMetadataTransport()
    workflow = SecretMetadataLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SecretMetadataLiveWorkflowError):
        workflow.execute("secret-metadata-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [(FOLDER_PATH, SECRET_NAME, TEMPLATE)]
    assert result["outcome"] == "succeeded"
    assert result["credential_material_supplied"] is False
    assert result["credential_material_returned"] is False
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_preview_and_prewrite_rechecks_reject_state_drift() -> None:
    transport = FakeSecretMetadataTransport()
    workflow = SecretMetadataLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.secret_exists = True

    with pytest.raises(SecretMetadataLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = FakeSecretMetadataTransport()
    workflow = SecretMetadataLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.folder_exists = False
    with pytest.raises(SecretMetadataLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert transport.create_calls == []

    transport = FakeSecretMetadataTransport()
    workflow = SecretMetadataLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.template_exists = False
    with pytest.raises(SecretMetadataLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeSecretMetadataTransport()
    transport.readback = SecretMetadataReadback(True, True, True, True, True)
    workflow = SecretMetadataLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SecretMetadataLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_out_of_scope_name_path_or_template() -> None:
    workflow = SecretMetadataLiveWorkflow(FakeSecretMetadataTransport())

    for folder_path, secret_name, template in (
        ("../unsafe", SECRET_NAME, TEMPLATE),
        (FOLDER_PATH, "outside-scope", TEMPLATE),
        (FOLDER_PATH, SECRET_NAME, "bad/template"),
    ):
        with pytest.raises(SecretMetadataLiveWorkflowError):
            workflow.preview(
                folder_path=folder_path,
                secret_name=secret_name,
                template=template,
                requester_digest=REQUESTER,
            )
