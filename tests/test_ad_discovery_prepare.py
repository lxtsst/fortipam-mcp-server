"""Offline AD inputs join the existing Draft and Reference authorities."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

import fortipam_mcp.ad_discovery_prepare as prepare
from fortipam_mcp.ad_discovery_projection_source import (
    SOURCE_REF, ad_discovery_projection_contract,
)
from fortipam_mcp.ad_discovery_runtime_config import load_ad_discovery_runtime_binding
from fortipam_mcp.linux_onboarding_prepare import DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME
from fortipam_mcp.reference_grant_bootstrap import (
    ReferenceGrantBootstrapSettings, bootstrap_reference_grants,
)
from fortipam_mcp.scheme_draft_bootstrap import (
    SchemeDraftBootstrapSettings, bootstrap_scheme_draft,
)
from scripts.v4_registry import load_registry
from test_ad_discovery_runtime_config import files
from v4_planning import (
    AuthenticatedRequester, AuthoritativeProjection, ChangeKind, M2PlanningEngine,
    ObjectClass, PersistentReferenceAuthority, PersistentSchemeDraftAuthority,
    SchemeId, scheme_draft_from_mapping,
)


NOW = 1_950_000_000
AUDIENCE = "ad-preparation-audience-ref01"
REQUESTER = AuthenticatedRequester("ad-preparation-requester-ref01", "operator")
RESULT = {
    "status": "prepared", "blueprint_ref": "FPA-BP-014", "object_count": 5,
    "material_provider_used": False, "device_contacted": False,
    "execution_authorized": False,
}


@pytest.fixture
def bundle(files, tmp_path):
    path, payload, domain_path, domain = files
    domain = {**domain, "requester_digest": REQUESTER.digest,
              "secret_name": "private-preparation-secret-marker",
              "target_name": "private-preparation-target-marker"}
    domain_path.write_text(json.dumps(domain))
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    return path, output, payload, domain_path, domain


def _prepare(bundle, **kwargs):
    path, output, *_ = bundle
    return prepare.prepare_ad_discovery_bundle(
        path, output, **{"audience_ref": AUDIENCE, "now_epoch": NOW,
                        "expires_at": NOW + 300, **kwargs},
    )


def _deny(bundle, **kwargs):
    with pytest.raises(prepare.AdDiscoveryPrepareError) as caught:
        _prepare(bundle, **kwargs)
    assert str(caught.value) == "AD Discovery preparation is unavailable."
    assert caught.value.__suppress_context__


def _inputs(output):
    return tuple(json.loads((output / name).read_text()) for name in (DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME))


def test_exact_five_object_inputs_hide_selectors_and_authorize_no_execution(bundle):
    path, output, payload, domain_path, domain = bundle
    snapshots = {item: item.read_bytes() for item in (path, domain_path)}
    binding = load_ad_discovery_runtime_binding(path)
    result = _prepare(bundle)
    assert result == RESULT
    assert all(type(result[name]) is bool for name in (
        "material_provider_used", "device_contacted", "execution_authorized",
    ))
    assert {item.name for item in output.iterdir()} == {DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME}
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in output.iterdir())
    assert all(item.read_bytes() == value for item, value in snapshots.items())
    draft_input, reference_input = _inputs(output)
    assert set(draft_input) == {"draft", "expires_at", "requester_digest"}
    assert set(reference_input) == {"environment_ref", "expires_at", "references", "requester_digest", "scope_ref"}
    assert draft_input["requester_digest"] == reference_input["requester_digest"] == REQUESTER.digest
    assert draft_input["expires_at"] == reference_input["expires_at"] == NOW + 300
    draft = scheme_draft_from_mapping(draft_input["draft"])
    binding.validate_intent(draft, REQUESTER)
    assert draft.scheme_id is SchemeId.BULK_ONBOARDING
    assert draft.scheme_version == "1.0.0"
    assert draft.blueprint_ref == "FPA-BP-014"
    assert draft.outcome_code == "create_disabled_ad_discovery_source"
    assert draft.risk_class == "medium"
    assert draft.audience_ref == AUDIENCE
    assert draft.material_reference_metadata is None
    assert len(draft.desired_objects) == 5
    assert {item.object_ref: (item.object_class, dict(item.desired_fields)) for item in draft.desired_objects} == binding.expected_objects()
    expected_grants = {
        (draft.environment_ref, "environment"), (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"), (AUDIENCE, "audience"),
        *((ref, "evidence") for ref in draft.evidence_refs),
        (SOURCE_REF, "projection_source"),
        (binding.domain.folder_object_ref, "object_folder_binding"),
        (binding.domain.target_object_ref, "object_domain_target_binding"),
        (binding.domain.template_object_ref, "object_template_binding"),
        (binding.domain.secret_object_ref, "object_domain_secret_metadata"),
        (binding.source_object_ref, "object_discovery_source_metadata"),
        (binding.domain.folder_ref, "field_folder_ref"),
        (binding.domain.target_profile_ref, "field_profile_ref"),
        (binding.domain.template_ref, "field_template_ref"),
        (binding.domain.secret_object_ref, "field_domain_secret_ref"),
    }
    references = reference_input["references"]
    assert all(set(item) == {"reference", "reference_kind"} for item in references)
    assert len(references) == len(expected_grants)
    assert {(item["reference"], item["reference_kind"]) for item in references} == expected_grants
    public = json.dumps((draft_input, reference_input))
    def integers(value):
        if type(value) is int:
            return [value]
        if type(value) is dict:
            return [number for item in value.values() for number in integers(item)]
        if type(value) is list:
            return [number for item in value for number in integers(item)]
        return []

    assert payload["discovery_secret_id"] not in integers([draft_input, reference_input])
    for private in (
        str(path), str(domain_path), payload["source_name"], domain["folder_path"],
        domain["secret_name"], domain["target_name"], domain["target_ipv4_address"],
        domain["domain_dns_root"], domain["target_owner_name"],
        binding.source.private_nonce, binding.source.parameters_digest,
        "discovery_secret_id", "domain_binding_file", "private_nonce", "parameters_digest",
    ):
        assert private not in public


def test_inputs_join_real_persistent_bootstrap_authorities_and_compile(bundle, tmp_path):
    path, output, *_ = bundle
    _prepare(bundle)
    draft_input, reference_input = _inputs(output)
    draft = scheme_draft_from_mapping(draft_input["draft"])
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    draft_key, reference_key = state / "draft.hmac", state / "reference.hmac"
    for key, content in ((draft_key, b"d" * 32), (reference_key, b"r" * 32)):
        key.write_bytes(content)
        key.chmod(0o600)
    draft_settings = SchemeDraftBootstrapSettings(
        state / "draft.sqlite3", draft_key, "ad-preparation-draft-authority",
        output / DRAFT_INPUT_NAME, state / "draft-result.json",
    )
    reference_settings = ReferenceGrantBootstrapSettings(
        state / "reference.sqlite3", reference_key, "ad-preparation-reference-authority",
        output / REFERENCE_INPUT_NAME, state / "reference-result.json",
    )
    bootstrap_scheme_draft(draft_settings, now_epoch=NOW)
    bootstrap_reference_grants(reference_settings, now_epoch=NOW)
    draft_ref = json.loads(draft_settings.output_path.read_text())["scheme_draft_ref"]
    authority = PersistentSchemeDraftAuthority(
        draft_settings.database_path, draft_key, authority_ref=draft_settings.authority_ref,
        clock=lambda: NOW,
    )
    assert authority.resolve(draft_ref, REQUESTER) == draft
    refs = PersistentReferenceAuthority(
        reference_settings.database_path, reference_key,
        authority_ref=reference_settings.authority_ref, clock=lambda: NOW,
    )
    assert all(refs.authorize(
        item["reference"], reference_kind=item["reference_kind"],
        requester_digest=REQUESTER.digest, environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref, now_epoch=NOW,
    ).authorized for item in reference_input["references"])

    class Issuer:
        count = 0

        def issue(self, purpose):
            self.count += 1
            return f"ad-prepare-{purpose}-{self.count:04d}"

    engine = M2PlanningEngine(
        load_registry(), Issuer(), refs,
        projection_contract_resolver=lambda scheme, cls: ad_discovery_projection_contract(cls),
    )
    # Offline shape/grant evidence only; these are not device qualification reads.
    projections = tuple(AuthoritativeProjection.from_mapping(
        contract=ad_discovery_projection_contract(item.object_class), object_ref=item.object_ref,
        observed_at=NOW, fresh_until=NOW + 300,
        fields={"exists": False} if item.object_class is ObjectClass.DISCOVERY_SOURCE_METADATA
        else {"exists": True, **dict(item.desired_fields)},
    ) for item in draft.desired_objects)
    summary = engine.compile_summary(draft, REQUESTER, projections, now_epoch=NOW)
    changes = {item.object_ref: item.change_kind for item in summary.object_changes}
    binding = load_ad_discovery_runtime_binding(path)
    assert changes[binding.source_object_ref] is ChangeKind.CREATE
    assert all(changes[ref] is ChangeKind.NO_OP for ref in binding.domain.expected_objects())
    assert len(summary.object_changes) == 5


def test_repeated_inputs_preserve_fixed_refs_and_relations(bundle, tmp_path):
    _prepare(bundle)
    first = scheme_draft_from_mapping(_inputs(bundle[1])[0]["draft"])
    other = tmp_path / "other-output"
    other.mkdir(mode=0o700)
    _prepare((bundle[0], other, *bundle[2:]))
    second = scheme_draft_from_mapping(_inputs(other)[0]["draft"])
    assert first.desired_objects == second.desired_objects
    assert (first.environment_ref, first.scope_ref, first.audience_ref) == (second.environment_ref, second.scope_ref, second.audience_ref)


@pytest.mark.parametrize("now,expiry", [
    (True, NOW + 300), (NOW, True), (NOW + 0.0, NOW + 300), (NOW, NOW + 300.0),
    (-1, 100), (NOW, NOW), (NOW, NOW - 1), (NOW, NOW + 301),
    (2**31 - 2, 2**31 - 1),
])
def test_native_bounded_clock_rejected_before_output(bundle, now, expiry):
    _deny(bundle, now_epoch=now, expires_at=expiry)
    assert list(bundle[1].iterdir()) == []


@pytest.mark.parametrize("audience", [None, True, "", "invalid audience ref"])
def test_audience_rejected_before_output(bundle, audience):
    _deny(bundle, audience_ref=audience)
    assert list(bundle[1].iterdir()) == []


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o500])
def test_output_requires_exact_0700_before_any_write(bundle, monkeypatch, mode):
    bundle[1].chmod(mode)
    original_open = os.open
    creates = []

    def observed_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            creates.append(path)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", observed_open)
    _deny(bundle)
    assert creates == []
    assert list(bundle[1].iterdir()) == []


@pytest.mark.parametrize("which", ["binding", "domain"])
def test_private_inputs_retain_loader_permission_boundary(bundle, which):
    (bundle[0] if which == "binding" else bundle[3]).chmod(0o644)
    _deny(bundle)
    assert list(bundle[1].iterdir()) == []


def test_output_symlink_component_and_relative_or_missing_directory_rejected(bundle, tmp_path):
    ancestor_link = tmp_path / "linked-parent"
    ancestor_link.symlink_to(tmp_path, target_is_directory=True)
    for output in (ancestor_link / "output", Path("relative-output"), tmp_path / "missing"):
        _deny((bundle[0], output, *bundle[2:]))
    assert list(bundle[1].iterdir()) == []


def test_wrong_output_owner_rejected_before_writing(bundle, monkeypatch):
    original_lstat = Path.lstat

    def wrong_owner(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == bundle[1]:
            values = list(info)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", wrong_owner)
    _deny(bundle)
    assert list(bundle[1].iterdir()) == []


def test_epoch_zero_is_valid_without_device_qualification(bundle):
    assert _prepare(bundle, now_epoch=0, expires_at=300) == RESULT
    draft_input, refs = _inputs(bundle[1])
    assert draft_input["expires_at"] == refs["expires_at"] == 300


@pytest.mark.parametrize("name", [DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME])
@pytest.mark.parametrize("symlink", [False, True])
def test_existing_outputs_never_overwritten_or_removed(bundle, tmp_path, name, symlink):
    existing = bundle[1] / name
    if symlink:
        target = tmp_path / "unrelated.json"
        target.write_text("preserve-existing")
        existing.symlink_to(target)
    else:
        existing.write_text("preserve-existing")
    _deny(bundle)
    assert existing.read_text() == "preserve-existing"
    assert {item.name for item in bundle[1].iterdir()} == {name}


def test_second_write_failure_removes_only_first_created_output(bundle, monkeypatch):
    preserved = bundle[1] / "unrelated.json"
    preserved.write_text("preserve-unrelated")
    original_open = os.open
    created = []

    def failing_open(path, flags, *args, **kwargs):
        if Path(path).name == REFERENCE_INPUT_NAME and flags & os.O_CREAT:
            raise OSError("private write failure marker")
        if Path(path).name == DRAFT_INPUT_NAME and flags & os.O_CREAT:
            assert flags & os.O_EXCL
            created.append(path)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", failing_open)
    _deny(bundle)
    assert len(created) == 1
    assert {item.name for item in bundle[1].iterdir()} == {preserved.name}
    assert preserved.read_text() == "preserve-unrelated"


@pytest.mark.parametrize("failure", [False, True])
def test_cli_output_is_categorical_and_private_values_never_printed(bundle, failure):
    path, output, payload, domain_path, _ = bundle
    prefix = "FORTIPAM_MCP_V4_AD_DISCOVERY_PREPARE_"
    environment = {
        prefix + "BINDING_FILE": str(path), prefix + "OUTPUT_DIRECTORY": str(output),
        prefix + "AUDIENCE_REF": AUDIENCE,
        prefix + "EXPIRES_AT": "invalid-private-marker" if failure else str(int(time.time()) + 180),
    }
    result = subprocess.run(
        [sys.executable, "-m", "fortipam_mcp.ad_discovery_prepare"],
        env=environment, cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == (1 if failure else 0)
    if failure:
        assert result.stdout == ""
        assert json.loads(result.stderr) == {"status": "failed"}
        assert list(output.iterdir()) == []
    else:
        assert json.loads(result.stdout) == RESULT
        assert result.stderr == ""
    for private in (str(path), str(domain_path), payload["source_name"], "invalid-private-marker"):
        assert private not in result.stdout + result.stderr
