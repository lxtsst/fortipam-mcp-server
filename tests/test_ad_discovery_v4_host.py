"""Explicit AD host composition remains source-bound and execution opt-in."""

from dataclasses import replace

import pytest

from fortipam_mcp.local_oauth import LocalOAuthProvider, LocalOAuthSettings, hash_local_password
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings, V4PersistentSchemeDraftAuthoritySettings,
    V4SyntheticHostSettings, V4RuntimeHostError, ad_discovery_v4_plan_host_factory,
    synthetic_v4_plan_host_factory,
)
from test_ad_discovery_projection_source import _prepared_source
from test_v4_planning import NOW
from test_ad_discovery_lab_auto_runtime import _context
from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError


def _host_settings(tmp_path):
    directory = tmp_path / "host"
    directory.mkdir(mode=0o700)

    def key(name, marker):
        path = directory / name
        path.write_bytes(marker * 32)
        path.chmod(0o600)
        return path

    settings = V4SyntheticHostSettings(
        directory / "planning.sqlite3", key("planning.hmac", b"p"),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            directory / "references.sqlite3", key("references.hmac", b"f"),
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            directory / "drafts.sqlite3", key("drafts.hmac", b"d"),
        ), host_mode="source-backed-ad-discovery",
    )
    confirmation = V4ConfirmationSettings(
        directory / "confirmation.sqlite3", key("confirmation.hmac", b"c"),
        key("receipts.hmac", b"r"),
    )
    provider = LocalOAuthProvider(LocalOAuthSettings(
        issuer="https://mcp.example.test/oauth", resource="https://mcp.example.test/mcp",
        database_path=directory / "oauth.sqlite3", username="operator",
        password_hash=hash_local_password("synthetic-host-password", salt=b"0123456789abcdef"),
    ))
    return settings, provider, confirmation


def test_explicit_ad_factory_binds_fixed_source_and_retains_read_only_startup(tmp_path, monkeypatch):
    _, source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    settings, provider, confirmation = _host_settings(tmp_path)
    factory = ad_discovery_v4_plan_host_factory(
        settings, binding=source._binding, owner_transport=source._owner,
        source_transport=source._source_transport, clock=lambda: NOW,
    )
    components = factory(provider, confirmation)
    assert components.ad_discovery_projection_source is not None
    assert components.ad_discovery_projection_source._binding == source._binding
    assert components.secret_onboarding_projection_source is None
    assert components.reference_authority is not None
    assert components.scheme_draft_authority is not None
    assert writes["calls"] == state["calls"] == []
    assert state["credentials"] == store.claim_count == writes["posts"] == 0


@pytest.mark.parametrize("missing", ["reference", "draft", "mode"])
def test_ad_factory_requires_both_authorities_and_its_exact_mode(tmp_path, monkeypatch, missing):
    _, source, _, writes, state = _prepared_source(tmp_path, monkeypatch)
    settings, _, _ = _host_settings(tmp_path)
    changes = {"reference_authority": None} if missing == "reference" else (
        {"scheme_draft_authority": None} if missing == "draft" else {"host_mode": "synthetic"}
    )
    with pytest.raises(V4RuntimeHostError):
        ad_discovery_v4_plan_host_factory(
            replace(settings, **changes), binding=source._binding,
            owner_transport=source._owner, source_transport=source._source_transport,
        )
    assert writes["calls"] == state["calls"] == []
    assert state["credentials"] == 0


def test_ad_mode_cannot_fall_back_to_synthetic_projections(tmp_path):
    settings, _, _ = _host_settings(tmp_path)
    with pytest.raises(V4RuntimeHostError, match="fixed projection"):
        synthetic_v4_plan_host_factory(settings)


def test_host_coordinator_uses_fixed_binding_and_preserves_closed_gate(tmp_path, monkeypatch):
    draft, plan, principal, source, _, runner_factory, _, store, writes, state = _context(
        tmp_path, monkeypatch, gate=None,
    )
    settings, provider, confirmation = _host_settings(tmp_path)
    components = ad_discovery_v4_plan_host_factory(
        settings, binding=source._binding, owner_transport=source._owner,
        source_transport=source._source_transport, clock=lambda: NOW,
    )(provider, confirmation)
    before = (len(writes["calls"]), len(state["calls"]), state["credentials"])
    coordinator = components.bind_ad_discovery_action_coordinator(runner_factory)
    with pytest.raises(FixedActionResolutionError):
        coordinator._resolver.bind_prepared(plan, draft, principal)
    assert before == (len(writes["calls"]), len(state["calls"]), state["credentials"])
    assert store.claim_count == writes["posts"] == 0
    with pytest.raises(V4RuntimeHostError, match="unavailable"):
        replace(components, ad_discovery_projection_source=None).bind_ad_discovery_action_coordinator(
            runner_factory,
        )
