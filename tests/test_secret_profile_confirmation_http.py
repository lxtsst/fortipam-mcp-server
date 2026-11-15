"""Existing Web and RDP profiles expose their exact non-secret controls for review."""

from urllib.parse import urlsplit

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.secret_onboarding_projection_source import secret_onboarding_projection_contract
from test_target_bound_web_projection_reader import planning_source, Transport
from test_v4_confirmation_http import _service, SummaryReader, _csrf, PASSWORD, NAMESPACE
from test_v4_planning import (
    NOW, _requester, _engine, _projection, _web_account_draft, _existing_web_service_draft,
    _existing_web_service_projections, _existing_secret_controls_draft, _existing_controls_projections,
    _winrm_collector_draft, _collector_projections, _promoted_registry, Authorizer, Issuer,
)
from v4_planning import M2PlanningEngine, ObjectClass


def _summary(profile):
    if profile == "target_web":
        draft, source = planning_source(Transport())
        authority = Authorizer((draft,), projection_source_ref="fortipam-191-secret-onboarding-projection")
        authority._grants.add(("fortipam-700-target-bound-web-projection", "projection_source"))
        engine = M2PlanningEngine(_promoted_registry(), Issuer(), authority,
            projection_contract_resolver=lambda scheme, cls: secret_onboarding_projection_contract(cls))
        projections = source.project(draft, _requester(), now_epoch=NOW)
    else:
        draft = {"web": _web_account_draft, "web_service": _existing_web_service_draft,
                 "rdp_controls": _existing_secret_controls_draft, "collector": _winrm_collector_draft}[profile]()
        engine = _engine(draft)
        if profile == "web":
            projections = [_projection(engine, draft.scheme_id, item,
                {"exists": False} if item.object_class is ObjectClass.WEB_SECRET_METADATA
                else {"exists": True, **dict(item.desired_fields)}) for item in draft.desired_objects]
        else:
            projections = {"web_service": _existing_web_service_projections,
                          "rdp_controls": _existing_controls_projections,
                          "collector": _collector_projections}[profile](engine, draft)
    return engine.compile_summary(draft, _requester(), projections, now_epoch=NOW)


@pytest.mark.parametrize("profile", ["web", "target_web", "web_service", "rdp_controls", "collector"])
def test_actual_profile_summary_is_visible_only_after_reauthentication(tmp_path, profile):
    summary = _summary(profile)
    service, clock, _ = _service(tmp_path)
    service._summary_reader = SummaryReader(summary)
    path = urlsplit(service.issue(summary, _requester(), principal_namespace_digest=NAMESPACE,
                                now_epoch=clock.value)).path
    with TestClient(Starlette(routes=service.routes()), base_url="https://mcp.example.com") as client:
        initial = client.get(path)
        assert summary.outcome_code not in initial.text
        assert "session_recording" not in initial.text
        review = client.post(path, data={"csrf_token": _csrf(initial.text), "username": "operator",
            "password": PASSWORD, "action": "review"}, headers={"origin": "https://mcp.example.com"})
        assert review.status_code == 200
        body = review.text
        for change in summary.object_changes:
            for field, _ in change.expected_fields:
                if not field.endswith("_digest"):
                    assert f"<th>{field}</th>" in body
            for field, value in change.expected_fields:
                if field.endswith("_digest"):
                    assert field not in body and str(value) not in body
        for private_field in ("password", "folder_path", "target_name", "secret_name", "owner_ref",
                              "material_reference_metadata"):
            assert f"<th>{private_field}</th>" not in body
        assert summary.environment_ref not in body and summary.scope_ref not in body
        if profile == "rdp_controls":
            current, remainder = body.split("<h3>SecretSessionControlsBinding: update</h3>")[1].split("<h4>Proposed", 1)
            assert "<th>clipboard_blocking_enabled</th><td>false</td>" in current
            assert "<th>clipboard_blocking_enabled</th><td>true</td>" in remainder
        if profile == "web_service":
            assert "<th>http_service_enabled</th><td>false</td>" in body
            assert "<th>http_service_enabled</th><td>true</td>" in body
