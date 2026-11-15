"""Concrete protected-file resolution using disposable synthetic inputs only."""
import copy
import json
import pickle

import pytest
import yaml

from fortipam_mcp import scim_client_central_lab_resolver as source
from fortipam_mcp.scim_client_contract import (ScimClientContractError, ScimNonmaterialState, build_scim_request_with_material,
    prepare_scim_rotate)
from fortipam_mcp.scim_client_material import ScimMaterialBinding, ScimMaterialProvider
from test_scim_client_contract import CONTEXT, values
from v4_planning.material_provider import (MaterialAccessDenied, MaterialBindingStatus,
    MaterialLeaseRequest, MaterialProviderClass)
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome


def inputs(root):
    registry, env = root/'bindings.yaml', root/'material.env'
    entries = [dict(id='scim-old', provider='env-file', variables={'password':'SCIM_OLD'}),
        dict(id='scim-new', provider='env-file', variables={'password':'SCIM_NEW'}),
        dict(id='unrelated-ssh', provider='env-file', variables={'ssh_username':'SSH_USER', 'ssh_password':'SSH_PASSWORD'})]
    registry.write_text(yaml.safe_dump(dict(schema_version='credential-bindings-v1', bindings=entries)))
    env.write_bytes(b"SCIM_OLD='synthetic-old-secret'\nSCIM_NEW=synthetic-new-secret\n")
    registry.chmod(0o600); env.chmod(0o600)
    return registry, env


def resolver(paths, selected='scim-new'):
    return source.ScimCentralLabMaterialResolver(credential_bindings_path=paths[0],
        secret_env_path=paths[1], credential_binding_id=selected)


def track_buffers(monkeypatch):
    buffers = []
    for name in ('_read_owner_only_file', '_read_owner_only_secret_env_file'):
        original = getattr(source, name)
        def read(path, original=original):
            result = original(path); buffers.append(result); return result
        monkeypatch.setattr(source, name, read)
    return buffers


def test_real_files_feed_only_the_owned_lease_and_native_codec(monkeypatch, tmp_path):
    paths = inputs(tmp_path); buffers = track_buffers(monkeypatch)
    old, new = resolver(paths, 'scim-old'), resolver(paths)
    assert old.binding_digest != new.binding_digest
    assert old.validate_prebound() is new.validate_prebound() is MaterialBindingStatus.AVAILABLE
    assert all(not any(raw) for raw in buffers)
    change = prepare_scim_rotate(ScimNonmaterialState.from_values(values()),
        current_material_binding_digest=old.binding_digest, replacement_material_binding_digest=new.binding_digest,
        context=CONTEXT)
    binding = ScimMaterialBinding(change)
    request = MaterialLeaseRequest(binding.action_id, '1.0.0', '3'*64, '4'*64, '5'*64, '6'*64, '7'*64,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, binding.purpose, 1000, 1060)
    provider = ScimMaterialProvider(new, binding, request, clock=lambda: 1000)
    views, bodies = [], []
    def consume(lease):
        def use(view):
            assert view.readonly; views.append(view)
            body = build_scim_request_with_material(change, view, current=change._original,
                context=CONTEXT, material_binding_digest=new.binding_digest)
            bodies.append(body)
            try: assert json.loads(body)['secret'] == 'synthetic-new-secret'
            finally: body[:] = b'\0'*len(body)
            return MaterialUseOutcome.VERIFIED
        return provider.consume(binding, lease, request, use)
    assert MaterialLeaseCoordinator(provider).execute_once(binding, request, consume,
        now_epoch=1000) is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    with pytest.raises(ValueError): bytes(views[0])
    with pytest.raises(MaterialAccessDenied): new.load_scim_material_once()
    assert all(not any(raw) for raw in buffers+bodies)
    assert old.validate_prebound() is MaterialBindingStatus.AVAILABLE
    original = old.load_scim_material_once()
    try: assert original == bytearray(b'synthetic-old-secret')
    finally: original[:] = b'\0'*len(original)
    assert 'synthetic' not in json.dumps(change.preview())


@pytest.mark.parametrize('failure', ['mode-registry', 'mode-env', 'symlink-registry', 'symlink-env',
    'missing', 'duplicate', 'duplicate-unrelated', 'oversize', 'invalid-utf8', 'nul', 'cr', 'empty', 'quoted-space'])
def test_unavailable_sources_never_extract_and_failed_load_is_terminal(monkeypatch, tmp_path, failure):
    paths = inputs(tmp_path); value = resolver(paths); buffers = track_buffers(monkeypatch)
    registry, env = paths
    if failure.startswith('mode-'): paths[0 if failure.endswith('registry') else 1].chmod(0o644)
    elif failure.startswith('symlink-'):
        selected = paths[0 if failure.endswith('registry') else 1]
        moved = selected.with_suffix('.original'); selected.rename(moved); selected.symlink_to(moved)
    else:
        content = {'missing': b'UNRELATED=synthetic\n', 'duplicate': b'SCIM_NEW=a\nSCIM_NEW=b\n',
            'duplicate-unrelated': b'SCIM_NEW=a\nOTHER=b\nOTHER=c\n', 'oversize': b'SCIM_NEW='+b'a'*60+b'\n',
            'invalid-utf8': b'SCIM_NEW=\xff\n', 'nul': b'SCIM_NEW=a\0b\n', 'cr': b'SCIM_NEW=ab\r\n',
            'empty': b'SCIM_NEW=\n', 'quoted-space': b"SCIM_NEW=' synthetic '\n"}[failure]
        env.write_bytes(content)
    assert value.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied, match='unavailable'): value.load_scim_material_once()
    if registry.is_symlink(): registry.unlink()
    if env.is_symlink(): env.unlink()
    inputs(tmp_path)
    with pytest.raises(MaterialAccessDenied): value.load_scim_material_once()
    assert all(not any(raw) for raw in buffers)


@pytest.mark.parametrize('failure', ['extra-role', 'token-role', 'unknown-role', 'duplicate-id', 'wrong-provider',
    'wrong-schema', 'missing-id', 'bad-variable', 'relative-path'])
def test_registry_shape_and_selected_password_role_are_fixed(tmp_path, failure):
    paths = inputs(tmp_path); raw = yaml.safe_load(paths[0].read_bytes())
    selected = raw['bindings'][1]
    if failure == 'extra-role': selected['variables']['username'] = 'SCIM_USER'
    elif failure == 'token-role': selected['variables'] = {'token':'SCIM_TOKEN'}
    elif failure == 'unknown-role': raw['bindings'][-1]['variables']['unknown'] = 'UNKNOWN'
    elif failure == 'duplicate-id': raw['bindings'].append(selected.copy())
    elif failure == 'wrong-provider': selected['provider'] = 'process-env'
    elif failure == 'wrong-schema': raw['schema_version'] = 'credential-bindings-v2'
    elif failure == 'missing-id': selected['id'] = 'scim-other'
    elif failure == 'bad-variable': selected['variables']['password'] = 'BAD VARIABLE'
    else: paths = (paths[0].relative_to(tmp_path), paths[1])
    if failure != 'relative-path': paths[0].write_text(yaml.safe_dump(raw))
    with pytest.raises(MaterialAccessDenied, match='unavailable'): resolver(paths)


def test_metadata_drift_closes_original_reference_and_aliases_cannot_invent_rotation(tmp_path):
    paths = inputs(tmp_path); value = resolver(paths)
    raw = yaml.safe_load(paths[0].read_bytes())
    raw['bindings'].append(dict(id='scim-alias', provider='env-file', variables={'password':'SCIM_NEW'}))
    paths[0].write_text(yaml.safe_dump(raw))
    assert value.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied): value.load_scim_material_once()
    current, alias = resolver(paths), resolver(paths, 'scim-alias')
    assert current.binding_digest == alias.binding_digest
    with pytest.raises(ScimClientContractError):
        prepare_scim_rotate(ScimNonmaterialState.from_values(values()),
            current_material_binding_digest=current.binding_digest, replacement_material_binding_digest=alias.binding_digest,
            context=CONTEXT)


def test_reference_is_not_a_secret_hash_and_source_is_not_renderable_or_copyable(tmp_path):
    paths = inputs(tmp_path); value = resolver(paths)
    paths[1].write_bytes(b'SCIM_OLD=synthetic-changed-old\nSCIM_NEW=synthetic-changed-new\n')
    assert value.binding_digest == resolver(paths).binding_digest
    assert value.validate_prebound() is MaterialBindingStatus.AVAILABLE
    assert 'scim-new' not in repr(value) and str(tmp_path) not in repr(value)
    for transform in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): transform(value)
    value.close()
    assert value.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied): value.load_scim_material_once()


def test_interruption_clears_file_buffer_and_does_not_restart_loading(monkeypatch, tmp_path):
    value = resolver(inputs(tmp_path)); buffers = track_buffers(monkeypatch)
    monkeypatch.setattr(source, '_valid_material_view', lambda view: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt): value.load_scim_material_once()
    assert all(not any(raw) for raw in buffers)
    with pytest.raises(MaterialAccessDenied): value.load_scim_material_once()


def test_concrete_resolvers_drive_m4_apply_and_separately_authorized_restore(monkeypatch, tmp_path):
    from fortipam_mcp.scim_client_m4_adapter import ScimExecutionEvidence, ScimLocalM4Adapter
    from test_scim_client_m4_adapter import Backend, Clock, SCOPE, Verifier, grant, stores
    from v4_planning import M4ExecutionKernel

    paths = inputs(tmp_path); buffers = track_buffers(monkeypatch)
    old, new = resolver(paths, 'scim-old'), resolver(paths)
    change = prepare_scim_rotate(ScimNonmaterialState.from_values(values()),
        current_material_binding_digest=old.binding_digest, replacement_material_binding_digest=new.binding_digest,
        context=CONTEXT)
    clock = Clock(); backend = Backend(clock, change)
    store, material = stores(tmp_path)
    # The product and independent observations remain synthetic. The actual
    # registry/file parser, lease, M4 kernel and both durable ledgers compose.
    class Evidence:
        def observe(self, configuration_digest):
            observed = {'synthetic-old-secret':old.binding_digest,
                'synthetic-new-secret':new.binding_digest}[backend.material]
            return ScimExecutionEvidence(configuration_digest, SCOPE.credential_source_digest,
                SCOPE.effects_source_digest, observed, SCOPE.effects_digest, 0, True, True, clock(), clock()+10)
    plan, authorization = grant(change, store, material); verifier = Verifier(plan, authorization)
    adapter = ScimLocalM4Adapter(change, backend, Evidence(), new, old, plan, authorization, store, material,
        scope=SCOPE, authorization_verifier=verifier, execution_enabled=True, source_guard=lambda: True, clock=clock)
    kernel = M4ExecutionKernel(adapter, verifier, store, clock=clock)
    assert kernel.execute(plan, authorization).outcome == 'succeeded'
    assert kernel.execute(plan, authorization).idempotent_replay and backend.sends == 1
    assert not old._attempted and new._attempted
    restore_plan, restore_auth = grant(change, store, material, True)
    restore_verifier = Verifier(restore_plan, restore_auth)
    restore = adapter.bind_restore(restore_plan, restore_auth, resolver=old,
        authorization_verifier=restore_verifier, execution_enabled=True)
    restore_kernel = M4ExecutionKernel(restore, restore_verifier, store, clock=clock)
    assert restore_kernel.execute(restore_plan, restore_auth).outcome == 'succeeded'
    assert restore_kernel.execute(restore_plan, restore_auth).idempotent_replay
    assert old._attempted and store.claim_count == material.claim_count == backend.sends == 2
    assert backend.material == 'synthetic-old-secret'
    assert all(not any(raw) for raw in buffers+backend.buffers)
    for path in tmp_path.iterdir():
        if path.suffix in ('.db', '.key'): assert b'synthetic-' not in path.read_bytes()


@pytest.mark.parametrize('content', [b'SCIM_NEW='+b'a'*59+b'\n',
    "SCIM_NEW='合成 secret'\n".encode('utf-8')])
def test_native_octet_limit_and_supported_quoted_utf8_values(tmp_path, content):
    paths = inputs(tmp_path); paths[1].write_bytes(content)
    value = resolver(paths)
    assert value.validate_prebound() is MaterialBindingStatus.AVAILABLE
    material = value.load_scim_material_once()
    try: assert 1 <= len(material) <= 59 and any(material)
    finally: material[:] = b'\0'*len(material)
