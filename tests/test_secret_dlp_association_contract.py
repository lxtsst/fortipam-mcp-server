from copy import deepcopy

import pytest

from fortipam_mcp.secret_dlp_association_contract import (
    FILTER_NAME, REGEXP_SENTINEL, SecretDlpAssociationContractError,
    compile_fixed_secret_dlp_body, fixed_log_only_sensor_digest,
    fixed_log_only_sensor_profile, project_secret_dlp_metadata,
)


def test_fixed_dlp_delta_and_inverse_require_native_profile_and_preservation() -> None:
    envelope = {"version": "v7.0.0", "build": 29, "status": "OK", "http_method": "GET",
                "http_status": 200, "path": "secret", "name": "database"}
    identity = {"id": 17, "folder": 9, "name": "mcp-v4-bp005-dlp-audit-synthetic",
                "template": "Unix Account (SSH Password)"}
    metadata = {**envelope, "results": {**identity, "target": "synthetic-target",
                "description": "Synthetic fixture", "proxy": "enable", "recording": "enable",
                "ssh-service-status": "up", "sftp-service-status": "up",
                "ssh-filter": "disable", "ssh-filter-profile": "", "dlp-status": "disable",
                "dlp-sensor": "", "field": None, "unrelated-setting": "unchanged"}}
    shape = [{"id": 1, "name": "Password", "type": "password"},
             {"id": 2, "name": "Username", "type": "username"},
             {"id": 3, "name": "Host", "type": "target-address"}]
    sensor_name = "mcp-v4-dlp-sftp-audit-synthetic"
    sensor = {**envelope, "path": "dlp", "name": "sensor", "results": {
        "name": sensor_name, "comment": "", "dlp-log": "enable", "extended-log": "disable",
        "nac-quar-log": "disable", "q_origin_key": sensor_name,
        "full-archive-proto": "", "summary-proto": "", "replacemsg-group": "", "filter": [{
            "id": 1, "name": FILTER_NAME, "type": "file", "proto": "http-get http-post",
            "q_origin_key": 1,
            "filter-by": "regexp", "regexp": REGEXP_SENTINEL, "file-size": 10,
            "file-type": 0, "sensitivity": [], "action": "log-only", "archive": "disable",
            "severity": "medium", "direction": "uplink", "company-identifier": "",
            "match-percentage": 10, "expiry": "5m"}]}}
    expected_post = deepcopy(sensor["results"])
    del expected_post["q_origin_key"]
    del expected_post["filter"][0]["q_origin_key"]
    assert fixed_log_only_sensor_profile(sensor_name=sensor_name) == expected_post
    fresh_profile = fixed_log_only_sensor_profile(sensor_name=sensor_name)
    fresh_profile["filter"][0]["sensitivity"].append({"name": "mutation"})
    assert fixed_log_only_sensor_profile(sensor_name=sensor_name) == expected_post
    before = project_secret_dlp_metadata(metadata, credential_shape=shape, opaque_field_digest="a" * 64)
    expected = {"identity": identity, "expected_sensor_name": sensor_name,
                "expected_sensor_digest": fixed_log_only_sensor_digest(sensor, expected_sensor_name=sensor_name),
                "expected_preservation_digest": before["preservation_digest"],
                "expected_credential_shape": shape, "expected_opaque_field_digest": "a" * 64}

    def compile(value: object = before, profile: object = sensor, **overrides: object) -> dict[str, object]:
        return compile_fixed_secret_dlp_body(value, profile, **{**expected, **overrides})

    original = deepcopy((metadata, sensor, shape, before))
    assert compile() == {**identity, "dlp-status": "enable", "dlp-sensor": sensor_name}
    # The actual native active-regexp shape omits exactly these two inactive defaults.
    active_sensor = deepcopy(sensor)
    del active_sensor["results"]["filter"][0]["file-size"]
    del active_sensor["results"]["filter"][0]["match-percentage"]
    assert len(active_sensor["results"]["filter"][0]) == 15
    assert fixed_log_only_sensor_digest(active_sensor, expected_sensor_name=sensor_name) == expected["expected_sensor_digest"]
    assert compile(profile=active_sensor) == compile()
    associated = deepcopy(metadata)
    associated["results"].update({"dlp-status": "enable", "dlp-sensor": sensor_name})
    after = project_secret_dlp_metadata(associated, credential_shape=shape, opaque_field_digest="a" * 64)
    assert after["preservation_digest"] == before["preservation_digest"]
    assert compile(after, restore=True) == {**identity, "dlp-status": "disable", "dlp-sensor": ""}
    assert (metadata, sensor, shape, before) == original
    assert "field" not in before["results"] and "unrelated-setting" not in before["results"]
    assert "target" not in compile() and "credential_shape" not in compile()

    # Restoration only consumes the exact association, never another Sensor or baseline.
    for row_field, replacement in (("template", "Windows Account"), ("id", True),
            ("dlp-status", "enable"), ("dlp-sensor", "another-sensor"),
            ("recording", "disable"), ("ssh-filter", "enable"),
            ("ssh-service-status", "enable"), ("sftp-service-status", "down"),
            ("ssh-filter-profile", "another-profile"), ("target", "drifted")):
        changed = deepcopy(before)
        changed["results"][row_field] = replacement
        with pytest.raises(SecretDlpAssociationContractError, match="unavailable"):
            compile(changed)
    with pytest.raises(SecretDlpAssociationContractError):
        compile(before, restore=True)
    with pytest.raises(SecretDlpAssociationContractError):
        compile(after)

    for changed_key, replacement in (("opaque_field_digest", "b" * 64),
                                     ("metadata_digest", "b" * 64), ("build", 30)):
        changed = deepcopy(before)
        changed[changed_key] = replacement
        with pytest.raises(SecretDlpAssociationContractError):
            compile(changed)
    missing = deepcopy(before)
    del missing["preservation_digest"]
    with pytest.raises(SecretDlpAssociationContractError):
        compile(missing)
    unknown_drift = deepcopy(metadata)
    unknown_drift["results"]["unrelated-setting"] = "drifted"
    drifted = project_secret_dlp_metadata(unknown_drift, credential_shape=shape, opaque_field_digest="a" * 64)
    with pytest.raises(SecretDlpAssociationContractError):
        compile(drifted)

    for field, replacement in (("action", "block"), ("proto", "ssh"),
                               ("type", "message"), ("regexp", "another-regexp"),
                               ("file-type", 1), ("sensitivity", [{"name": "another"}]),
                               ("id", True), ("archive", "enable"), ("direction", "downlink"),
                               ("company-identifier", "unexpected"), ("match-percentage", True),
                               ("q_origin_key", "1"),
                               ("unexpected-filter-option", "enable")):
        changed = deepcopy(sensor)
        changed["results"]["filter"][0][field] = replacement
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=changed)
    for field, replacement in (("filter", []), ("name", "another-sensor"),
                               ("summary-proto", "http-get"), ("full-archive-proto", "http-get")):
        changed = deepcopy(sensor)
        changed["results"][field] = replacement
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=changed)
    for field, replacement in (("extended-log", "enable"), ("replacemsg-group", "unexpected"),
                               ("nac-quar-log", "enable"), ("q_origin_key", True),
                               ("unexpected-option", "enable")):
        changed = deepcopy(sensor)
        changed["results"][field] = replacement
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=changed)
    for absent_field in ("comment", "extended-log", "full-archive-proto", "replacemsg-group",
                         "nac-quar-log", "q_origin_key"):
        changed = deepcopy(sensor)
        del changed["results"][absent_field]
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=changed)
    for absent_field in ("archive", "severity", "expiry", "file-type", "q_origin_key"):
        changed = deepcopy(active_sensor)
        del changed["results"]["filter"][0][absent_field]
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=changed)
    for absent in (None, {"qualified": True}, {**sensor, "http_status": 404},
                   {**sensor, "results": []}):
        with pytest.raises(SecretDlpAssociationContractError):
            compile(profile=absent)
    with pytest.raises(SecretDlpAssociationContractError):
        compile(expected_sensor_name="mcp-v4-dlp-sftp-audit-" + "x" * 20)

    # Only already-redacted input and structure-only descriptors may enter projection.
    unredacted = deepcopy(metadata)
    unredacted["results"]["field"] = []
    with pytest.raises(SecretDlpAssociationContractError):
        project_secret_dlp_metadata(unredacted, credential_shape=shape, opaque_field_digest="a" * 64)
    for altered in ([*shape, shape[0]], [shape[0]],
                    [{**shape[0], "value": "synthetic-denial-marker"}, *shape[1:]],
                    [{**shape[0], "id": True}, *shape[1:]],
                    [{**shape[0], "type": "private-key"}, *shape[1:]],
                    [*shape[:2], {**shape[2], "type": "address"}],
                    [*shape[:2], {**shape[2], "id": shape[0]["id"]}]):
        with pytest.raises(SecretDlpAssociationContractError):
            project_secret_dlp_metadata(metadata, credential_shape=altered, opaque_field_digest="a" * 64)
    with pytest.raises(SecretDlpAssociationContractError):
        compile(expected_credential_shape=shape[:2])


def test_native_active_regexp_shape_requires_origins_and_only_two_inactive_defaults() -> None:
    sensor_name = "mcp-v4-dlp-sftp-audit-native"
    # Independent shape matching the native regexp read, rather than a POST echo.
    native = {"version": "v7.0.0", "build": 29, "status": "OK", "http_method": "GET",
              "http_status": 200, "path": "dlp", "name": "sensor", "results": {
        "name": sensor_name, "q_origin_key": sensor_name, "comment": "", "dlp-log": "enable",
        "extended-log": "disable", "nac-quar-log": "disable", "replacemsg-group": "",
        "full-archive-proto": "", "summary-proto": "", "filter": [{
            "id": 1, "q_origin_key": 1, "name": "mcp-v4-dlp-file-audit", "type": "file",
            "proto": "http-get http-post", "filter-by": "regexp", "regexp": "MCP_V4_DLP_REGEX_SENTINEL",
            "action": "log-only", "archive": "disable", "severity": "medium", "direction": "uplink",
            "company-identifier": "", "expiry": "5m", "file-type": 0, "sensitivity": []}]}}
    original = deepcopy(native)
    digest = fixed_log_only_sensor_digest(native, expected_sensor_name=sensor_name)
    for inactive_defaults in ({"file-size": 10}, {"match-percentage": 10},
                              {"file-size": 10, "match-percentage": 10}):
        extended = deepcopy(native)
        extended["results"]["filter"][0].update(inactive_defaults)
        assert fixed_log_only_sensor_digest(extended, expected_sensor_name=sensor_name) == digest
    assert native == original
    for field, value in (("file-size", 11), ("match-percentage", 11), ("q_origin_key", True),
                         ("q_origin_key", "1"), ("filter-by", "file-size"), ("extra", "disable")):
        changed = deepcopy(native)
        changed["results"]["filter"][0][field] = value
        with pytest.raises(SecretDlpAssociationContractError):
            fixed_log_only_sensor_digest(changed, expected_sensor_name=sensor_name)
    for field, value in (("q_origin_key", "another-name"), ("nac-quar-log", "enable")):
        changed = deepcopy(native)
        changed["results"][field] = value
        with pytest.raises(SecretDlpAssociationContractError):
            fixed_log_only_sensor_digest(changed, expected_sensor_name=sensor_name)


def test_private_inspection_factory_binds_exact_sources_and_rejects_forged_snapshots() -> None:
    from dataclasses import FrozenInstanceError, replace
    import json

    from fortipam_mcp.secret_dlp_association_contract import (
        qualify_secret_dlp_association_inspection, validate_secret_dlp_association_inspection,
    )
    from test_secret_dlp_association_live_workflow import inspection

    current = inspection()
    assert validate_secret_dlp_association_inspection(current) == current
    assert current.identity.name not in repr(current) and current.sensor_name not in repr(current)
    with pytest.raises(FrozenInstanceError):
        current.actor_digest = "e" * 64
    for forged in (replace(current, actor_digest="e" * 64), replace(current, preservation_digest="e" * 64),
                   replace(current, native_sensor_json="{}"), replace(current, projected_secret_json="{}")):
        with pytest.raises(SecretDlpAssociationContractError):
            validate_secret_dlp_association_inspection(forged)
    projected = json.loads(current.projected_secret_json)
    sensor = json.loads(current.native_sensor_json)
    for absent in (None, {"qualified": True}, {**sensor, "http_status": 404}):
        with pytest.raises(SecretDlpAssociationContractError):
            qualify_secret_dlp_association_inspection(projected, absent, identity=current.identity,
                sensor_name=current.sensor_name, actor_digest=current.actor_digest,
                redacted_metadata_witness_digest=current.redacted_metadata_witness_digest)
    with pytest.raises(SecretDlpAssociationContractError):
        qualify_secret_dlp_association_inspection(projected, sensor,
            identity=replace(current.identity, target="another-target"), sensor_name=current.sensor_name,
            actor_digest=current.actor_digest, redacted_metadata_witness_digest=current.redacted_metadata_witness_digest)
    # Both shapes qualify semantically, while the current-state digest binds their exact native representation.
    sparse = inspection(omit_inactive=True)
    assert sparse.sensor_digest == current.sensor_digest and sparse.state_digest != current.state_digest
