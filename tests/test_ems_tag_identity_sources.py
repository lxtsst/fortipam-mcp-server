"""Complete fixed identity sources with synthetic HTTP, never native writes."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.ems_tag_http_transport import EmsTagHttpError
from fortipam_mcp.ems_tag_identity_contract import (
    ROLE_INDEX, ADMIN_INDEX, EmsTagIdentityScope, admin_catalog, admin_detail_path,
    qualify_admin_detail, role_catalog, verify_role_created, verify_role_restored,
)
from fortipam_mcp.ems_tag_identity_sources import NativeEmsIdentityHttpTransport, EmsTagIdentitySources
from fortipam_mcp.ems_tag_role_contract import ProspectiveEmsTagManagerRole, qualify_permission_schema, qualify_role_detail
from fortipam_mcp.ems_tag_sources import METADATA_PATH, CATALOG_PATH
from test_ems_tag_contract import envelope
from test_ems_tag_http_transport import make as base_http
from test_ems_tag_role_contract import permissions


def fixture():
    schema = qualify_permission_schema(permissions())
    draft = ProspectiveEmsTagManagerRole(schema, "a" * 32)
    role = {**draft._body, "id": 7, "uid": "synthetic-role", "is_built_in": False, "is_super": False}
    owner = {**role, "id": -1, "uid": "synthetic-super", "name": "synthetic-super", "is_built_in": True, "is_super": True}
    catalog = [{k: row[k] for k in ("uid", "name", "description", "is_built_in", "is_super")} for row in (role, owner)]
    user = {"id": 9, "name": "synthetic_owner", "vdom": None, "user_type": "BuiltIn", "role_uid": owner["uid"],
            "default_site_role_uid": None, "is_global": True, "trusted_hosts_enabled": False, "trusted_hosts": None,
            "allow_all_domains": True, "idps": [], "last_active_time": "synthetic-time", "other_config": {"enabled": False}}
    user_catalog = [{k: user[k] for k in ("id", "name", "vdom", "user_type")}]
    metadata = {"consts": {"System": {"VERSION_FULL": "7.4.8.2245", "VERSION": "7.4.8", "SITES_ENABLED": False},
        "CHROME": False, "SUCCESS": 1, "Permissions": permissions(), "User": {"Type": {"Builtin": "BuiltIn", "Ems": "EMS", "Ldap": "LDAP"}}},
        "User": {"name": user["name"], "is_global": True, "role": deepcopy(owner)},
        "ActiveVdom": "Default", "ShowGlobal": True, "ShowVdom": True}
    return dict(roles=catalog, details={role["uid"]: role, owner["uid"]: owner}, admins=user_catalog, user=user, metadata=metadata)


def make(tmp_path, monkeypatch, *, fault=None, shared_config=None, source_key=b"s" * 32, session_value="synthetic"):
    base, channel, connections, _, config, _ = base_http(tmp_path, monkeypatch)
    channel.session_value = session_value
    config = shared_config or config
    transport = NativeEmsIdentityHttpTransport(config, owner_credentials=lambda: ("synthetic_owner", "synthetic-only"))
    monkeypatch.setattr(transport, "_connect", base._connect)
    data = fixture();calls = []
    def get(path):
        calls.append(path)
        if path == METADATA_PATH:
            return envelope(data["metadata"])
        if path == ROLE_INDEX:
            return envelope(data["roles"])
        if path == ADMIN_INDEX:
            return envelope(data["admins"])
        if path.startswith("/api/v1/roles/"):
            value = deepcopy(data["details"][path.split("/")[-2]])
            if fault == "role_drift" and calls.count(path) == 2 and not value["is_super"]:value["view_group_assignment"] = False
            return envelope(value)
        if path in ("/api/v1/admins/9/get", "/api/v1/admins/9/get?vdom=Default"):
            value = deepcopy(data["site_user"] if "?" in path else data["user"])
            if calls.count(path) == 2:
                value["last_active_time"] = "another-runtime-time"
                if fault == "admin_drift":value["other_config"]["enabled"] = True
            return envelope(value)
        raise AssertionError("Unexpected synthetic route")
    channel.get = get
    transport.authenticate()
    now = [1000]
    source = EmsTagIdentitySources(transport, source_key=source_key, clock=lambda: now[0])
    return source, transport, calls, connections, data, now


def test_complete_scope_preserves_all_config_but_ignores_only_declared_last_active_time(tmp_path, monkeypatch):
    source, transport, calls, connections, _, _ = make(tmp_path, monkeypatch)
    observed = source.observe();source.check_current(observed)
    assert source._stage == "finished" and source._complete_passes == 2
    assert len(observed.full_scope._role_details) == 2 and len(observed.full_scope._admin_details) == 1
    assert observed.full_scope.role_is_referenced("synthetic-super")
    assert not observed.full_scope.role_is_referenced("synthetic-role")
    assert calls.count(ROLE_INDEX) == calls.count(ADMIN_INDEX) == 2 and calls.count(METADATA_PATH) == 2
    assert all(c.body is None for c in connections if c.path == ADMIN_INDEX)
    assert "synthetic_owner" not in repr(observed) + repr(observed.full_scope)
    with pytest.raises(ValueError): source.check_current(replace(observed))
    assert transport.close().next_session_check_401 and all(c.closed for c in connections)


def test_same_numeric_admin_id_in_distinct_vdoms_keeps_separate_native_routes_and_details(tmp_path, monkeypatch):
    source, transport, calls, _, data, _ = make(tmp_path, monkeypatch)
    user = {**deepcopy(data["user"]), "name": "synthetic-site-user", "vdom": "Default", "user_type": "SAML",
            "role_uid": None, "default_site_role_uid": None}
    data["site_user"] = user
    data["admins"].append({k: user[k] for k in ("id", "name", "vdom", "user_type")})
    observed = source.observe()
    assert len(observed.full_scope._admin_details) == 2
    assert calls.count("/api/v1/admins/9/get") == calls.count("/api/v1/admins/9/get?vdom=Default") == 2
    assert observed.full_scope.role_is_referenced("synthetic-super")
    source.close();assert transport.close().next_session_check_401


@pytest.mark.parametrize("fault", ["role_missing", "permission_mask", "admin_role", "global_admin"])
def test_authenticated_actor_must_join_the_exact_full_role_and_global_admin_record(tmp_path, monkeypatch, fault):
    source, transport, _, _, data, _ = make(tmp_path, monkeypatch)
    if fault == "role_missing":data["metadata"]["User"]["role"]["uid"] = "foreign-role"
    elif fault == "permission_mask":data["metadata"]["User"]["role"]["manage_server_settings"] = True
    elif fault == "admin_role":data["user"]["role_uid"] = "synthetic-role"
    else:data["user"]["is_global"] = False
    with pytest.raises(ValueError):source.observe()
    assert source._stage == "actor_scope_join" and transport.close().next_session_check_401


@pytest.mark.parametrize("fault", ["role_drift", "admin_drift"])
def test_complete_second_pass_detects_configuration_drift_and_closes_source(tmp_path, monkeypatch, fault):
    source, transport, calls, _, _, _ = make(tmp_path, monkeypatch, fault=fault)
    with pytest.raises(ValueError, match="^The private EMS identity source is unavailable\\.$"): source.observe()
    assert source._stage == "observation_comparison" and source._complete_passes == 2
    before = len(calls)
    with pytest.raises(ValueError): source.observe()
    assert len(calls) == before and transport.close().next_session_check_401


@pytest.mark.parametrize("path", [CATALOG_PATH, "/api/v1/roles/create", "/api/v1/roles/synthetic-role/delete",
    "/api/v1/admins/create", "/api/v1/admins/9/delete", "/api/v1/admins/9/get?vdom=Default", "/api/v1/endpoints/index"])
def test_unselected_or_configuration_routes_never_connect(tmp_path, monkeypatch, path):
    _, transport, _, connections, _, _ = make(tmp_path, monkeypatch)
    before = len(connections)
    with pytest.raises(EmsTagHttpError): transport.get_json(path)
    assert len(connections) == before and transport.close().next_session_check_401


@pytest.mark.parametrize("fault", ["expired", "rollback", "cookie", "permission", "reader"])
def test_fresh_source_rejects_expiry_session_schema_or_reader_changes(tmp_path, monkeypatch, fault):
    source, transport, _, _, data, now = make(tmp_path, monkeypatch)
    if fault == "permission":
        data["metadata"]["consts"]["Permissions"]["FOREIGN_PERMISSION"] = "foreign_permission"
        with pytest.raises(ValueError): source.observe()
    else:
        observed = source.observe()
        if fault == "expired":now[0] = 1060
        elif fault == "rollback":now[0] = 999
        elif fault == "cookie":
            next(c for c in transport._jar if c.name == "sessionid").value = "changed-synthetic-session"
        else:monkeypatch.setattr(transport, "get_json", lambda _: envelope(None))
        with pytest.raises(ValueError):source.check_current(observed)
    assert transport.close().next_session_check_401


def test_closed_scope_refuses_missing_duplicate_foreign_reference_or_nested_material():
    value = fixture();schema = qualify_permission_schema(permissions())
    roles = role_catalog(envelope(value["roles"]));admins = admin_catalog(envelope(value["admins"]))
    uidset = frozenset(value["details"])
    user = qualify_admin_detail(envelope(value["user"]), admins[0], uidset)
    details = tuple(qualify_role_detail(value["details"][json.loads(raw)["uid"]], schema) for raw in roles)
    scope = EmsTagIdentityScope(schema, roles, details, admins, (user,))
    assert scope.digest
    with pytest.raises(ValueError): replace(scope, _role_details=details[:1])
    with pytest.raises(ValueError): admin_catalog(envelope(value["admins"] * 2))
    with pytest.raises(ValueError): role_catalog(envelope(value["roles"] * 2))
    for patch in [{"role_uid": "foreign-role"}, {"other_config": {"password": "synthetic-only"}},
                  {"role_uid": None, "default_site_role_uid": None, "sites": [{"role_uid": "foreign-role"}]},
                  {"unknown_role_uid": "synthetic-role"}]:
        with pytest.raises(ValueError):qualify_admin_detail(envelope({**value["user"], **patch}), admins[0], uidset)
    assert admin_detail_path(admins[0]) == "/api/v1/admins/9/get"
    changed = json.loads(admins[0]);changed["vdom"] = "synthetic site"
    assert admin_detail_path(json.dumps(changed).encode()) == "/api/v1/admins/9/get?vdom=synthetic+site"


def test_role_birth_requires_exactly_one_unused_minimal_role_and_preserves_all_other_config():
    value = fixture();schema = qualify_permission_schema(permissions())
    draft = ProspectiveEmsTagManagerRole(schema, "b" * 32)
    def scope(data):
        rows = role_catalog(envelope([{k: row[k] for k in ("uid", "name", "description", "is_built_in", "is_super")}
                                      for row in data["details"].values()]))
        admins = admin_catalog(envelope(data["admins"]))
        details = tuple(qualify_role_detail(data["details"][json.loads(raw)["uid"]], schema) for raw in rows)
        user = qualify_admin_detail(envelope(data["user"]), admins[0], frozenset(data["details"]))
        return EmsTagIdentityScope(schema, rows, details, admins, (user,))
    baseline = scope(value)
    created_data = deepcopy(value)
    created_data["details"]["synthetic-new-role"] = {**draft._body, "id": 17, "uid": "synthetic-new-role",
                                                  "is_built_in": False, "is_super": False}
    created = scope(created_data)
    assert verify_role_created(baseline, created, draft)._uid == "synthetic-new-role"
    verify_role_restored(baseline, scope(deepcopy(value)))
    with pytest.raises(ValueError): verify_role_restored(baseline, created)
    with pytest.raises(ValueError): verify_role_created(baseline, baseline, draft)
    for fault in ("old_role", "admin_config", "new_reference", "super", "builtin", "permission", "numeric_id"):
        changed = deepcopy(created_data)
        role = changed["details"]["synthetic-new-role"]
        if fault == "old_role":changed["details"]["synthetic-role"]["manage_server_settings"] = True
        elif fault == "admin_config":changed["user"]["other_config"]["enabled"] = True
        elif fault == "new_reference":changed["user"]["role_uid"] = role["uid"]
        elif fault == "super":role["is_super"] = True
        elif fault == "builtin":role["is_built_in"] = True
        elif fault == "permission":role["view_group_assignment"] = False
        else:role["id"] = 7
        with pytest.raises(ValueError): verify_role_created(baseline, scope(changed), draft)
