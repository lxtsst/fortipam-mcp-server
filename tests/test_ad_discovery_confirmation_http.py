"""Confirmation displays typed C/P/E controls without private native selectors."""

from urllib.parse import urlsplit

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.v4_confirmation_http import _field_table
from test_ad_discovery_projection_source import _engine, _prepared_source
from test_v4_confirmation_http import NAMESPACE, PASSWORD, SummaryReader, _csrf, _service
from test_v4_planning import NOW, _requester
from v4_planning import ObjectClass


@pytest.mark.parametrize("object_class,fields", [
    (ObjectClass.PUBLIC_FOLDER, {"enabled": True, "exists": False}),
    (ObjectClass.ACCESS_GRANT, {"exists": True, "permission": "view", "subject_class": "user"}),
    (ObjectClass.SECRET_METADATA, {"exists": True, "inherit_permission": True}),
    (ObjectClass.TARGET, {"exists": True, "protocol": "ssh"}),
])
def test_existing_typed_object_classes_render_fields(object_class, fields):
    body = _field_table("Current", {**fields, "password": "private-field-sentinel"}, object_class.value)
    for field in fields:
        assert f"<th>{field}</th>" in body
    assert "private-field-sentinel" not in body
    assert "password" not in body


def test_ad_confirmation_review_shows_all_controls_after_reauthentication(tmp_path, monkeypatch):
    draft, source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    requester = _requester()
    summary = _engine(draft).compile_summary(
        draft, requester, source.project(draft, requester, now_epoch=NOW), now_epoch=NOW,
    )
    service, clock, _ = _service(tmp_path)
    service._summary_reader = SummaryReader(summary)
    path = urlsplit(service.issue(
        summary, requester, principal_namespace_digest=NAMESPACE, now_epoch=clock.value,
    )).path
    before = (len(writes["calls"]), len(state["calls"]), state["credentials"])
    with TestClient(Starlette(routes=service.routes()), base_url="https://mcp.example.com") as client:
        initial = client.get(path)
        assert "periodic_scanning_disabled" not in initial.text
        review = client.post(path, data={
            "csrf_token": _csrf(initial.text), "username": "operator", "password": PASSWORD,
            "action": "review",
        }, headers={"origin": "https://mcp.example.com"})
        assert review.status_code == 200
        body = review.text
        for change in summary.object_changes:
            assert change.object_class.value in body
            for field, _ in change.expected_fields:
                assert f"<th>{field}</th>" in body
        for field in ("periodic_scanning_disabled", "auto_onboarding_disabled", "no_scan_timestamp",
                      "non_privileged_account", "services_disabled", "target_association_matches"):
            assert f"<th>{field}</th><td>true</td>" in body
        assert source._binding.domain.secret_object_ref in body
        assert source._binding.source.request.source_name not in body
        assert summary.environment_ref not in body and summary.scope_ref not in body
        assert "private_binding_digest" not in body and "parameters_digest" not in body
        clock.value = NOW + 2
        confirmed = client.post(path, data={"csrf_token": _csrf(body), "action": "affirm"},
                                headers={"origin": "https://mcp.example.com"})
        assert confirmed.status_code == 200
    assert service.verify(requester, principal_namespace_digest=NAMESPACE,
        summary_ref=summary.summary_ref, summary_revision=summary.revision,
        now_epoch=clock.value).decision == "affirm"
    assert before == (len(writes["calls"]), len(state["calls"]), state["credentials"])
    assert store.claim_count == writes["posts"] == 0


def test_confirmation_field_values_are_escaped_and_unknown_classes_are_empty():
    fields = {"domain_secret_ref": '<img src=x onerror="alert(1)">',
              "password": "hidden-secret-sentinel"}
    body = _field_table("Proposed", fields, ObjectClass.DISCOVERY_SOURCE_METADATA.value)
    assert "&lt;img" in body and "<img" not in body and "hidden-secret-sentinel" not in body
    unknown = _field_table("Proposed", fields, "UnrecognizedClass")
    assert "domain_secret_ref" not in unknown and "hidden-secret-sentinel" not in unknown
