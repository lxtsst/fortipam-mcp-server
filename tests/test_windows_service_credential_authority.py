"""Fixed service issuers with real persistent M4/C3 and synthetic product IO."""
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_service_credential_authority as a
from fortipam_mcp import windows_service_credential_recovery_authority as ra
from fortipam_mcp import windows_service_credential_http_transport as http
from fortipam_mcp import windows_service_credential_readback as readback
from fortipam_mcp import windows_service_credential_recovery as recovery_module
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from fortipam_mcp.windows_service_credential_material import windows_service_credential_material_runtime
from test_m4_execution_store import _ExternalM4Checkpoint
from test_secret_create_m4_runtime import _Reader
from test_windows_service_credential_lifecycle import fixture, execute
from test_windows_service_credential_http_transport import Source
from test_windows_service_credential_recovery import Source as RecoverySource
from test_windows_privileged_secret_contract import binding as privileged_binding
from v4_planning import M4AuthorizationDenied, M4Outcome


def key(path, value):
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def setup(tmp_path, *, enabled=True):
    cmp = fixture(tmp_path)
    identity = dict(requester_digest=cmp['kwargs']['plan'].requester_digest, transport_digest='b' * 64)
    available = [True]
    kwargs = dict(profile=cmp['kwargs']['profile'], defaults=cmp['kwargs']['defaults'],
        material_binding=cmp['kwargs']['material_binding'], execution_store=cmp['execution'],
        material_store=cmp['material'], authority_key_file=key(tmp_path / 'authority.key', b'a' * 32),
        witness_key_file=cmp['key'], source_context_digest='c' * 64,
        environment_ref='owner-lab-development', scope_ref='one-service-credential', audience_ref='fixed-client',
        check_source=lambda: available[0], execution_enabled=enabled, clock=lambda: cmp['now'][0], **identity)
    authority = a.WindowsServiceCredentialLabAuthority(**kwargs)
    cmp.update(authority=authority, authority_kwargs=kwargs, identity=identity, available=available)
    return cmp


def issue(cmp):
    preview = cmp['authority'].preview(current_digest=a.windows_service_credential_state_digest(
        cmp['kwargs']['profile'], exists=False), **cmp['identity'])
    return cmp['authority'].issue(preview, **cmp['identity'])


def bind(cmp, monkeypatch, issued, *, read_fault=None):
    cmp['custody'].close()
    values = {**cmp['kwargs'], 'plan': issued.plan, 'authorization': issued.authorization,
        'request': issued.lease_request, 'material_binding': issued.material_binding}
    birth_kwargs = {**cmp['birth_kwargs'], **{k: values[k] for k in ('plan', 'authorization', 'request')}}
    custody = WindowsServiceCredentialBirthCustody(cmp['directory'], cmp['key'], **birth_kwargs)
    source = Source(read_fault=read_fault)
    monkeypatch.setattr(http, '_ssl_context', lambda config: ssl.create_default_context())
    monkeypatch.setattr(readback, '_ssl_context', lambda config: ssl.create_default_context())
    transport = http.WindowsServiceCredentialHttpTransport(birth_kwargs['config'], custody,
        execution_enabled=True, source_guard=source.guard, connection_factory=source.factory, http_clock=lambda: 0)
    material_runtime = windows_service_credential_material_runtime(**{**values, 'transport': transport})
    reader = _Reader(post=issued.plan.expected_state_digest,
        onboarding_binding_digest=values['profile'].parameters_digest)
    reader.read_current = lambda plan: plan.expected_current_digest
    outer = ProtectedSecretCreateM4Runtime(cmp['authority'], cmp['authority'], cmp['execution'], material_runtime,
        reader, authenticated_requester_digest=issued.plan.requester_digest, clock=lambda: cmp['now'][0])
    cmp.update(kwargs=values, birth_kwargs=birth_kwargs, custody=custody, bound=issued,
        outer=outer, source=source, transport=transport)


def independent_recovery(cmp, tmp_path, monkeypatch, *, fault=None, enabled=True):
    original = cmp['custody'].inspect_original_creation()
    cmp['authority'].close()
    cmp['custody'].close()
    cmp['now'][0] = 2000
    custody = WindowsServiceCredentialBirthCustody(cmp['directory'], cmp['key'], **cmp['birth_kwargs'])
    store = PersistentM4ExecutionStateStore(tmp_path / 'remove.sqlite', key(tmp_path / 'remove.key', b'r' * 32),
        monotonic_checkpoint=_ExternalM4Checkpoint('service-issuer-recovery'), checkpoint_store_ref='service-issuer-recovery')
    identity = dict(requester_digest=cmp['bound'].plan.requester_digest, transport_digest='d' * 64)
    kwargs = dict(execution_store=store, authority_key_file=key(tmp_path / 'remove-authority.key', b'h' * 32),
        witness_key_file=key(tmp_path / 'remove-witness.key', b'w' * 32), environment_ref='owner-lab-development',
        scope_ref='one-original-service-credential', audience_ref='independent-client', execution_enabled=enabled,
        clock=lambda: cmp['now'][0], **identity)
    authority = ra.WindowsServiceCredentialRemovalLabAuthority(custody, **kwargs)
    source = RecoverySource(fault)
    monkeypatch.setattr(recovery_module, '_ssl_context', lambda config: ssl.create_default_context())
    options = dict(execution_store=store, witness_key_file=tmp_path / 'remove-witness.key',
        config=replace(cmp['birth_kwargs']['config'], bearer_token='independent-synthetic-token'),
        authorization_verifier=authority, execution_enabled=True, source_guard=source.guard,
        connection_factory=source.factory, clock=lambda: cmp['now'][0], http_clock=lambda: 0)
    recovery = recovery_module.WindowsServiceCredentialRecovery(custody, **options)
    cmp.update(remove_authority=authority, remove_authority_kwargs=kwargs, recovery=recovery,
        recovery_kwargs=options, remove_source=source, remove_store=store, independent_custody=custody,
        recovery_identity=identity, original=original)


@pytest.mark.parametrize('missing_material_seal', [False, True])
def test_real_create_and_independent_recovery_issuers_preserve_original_custody_and_one_use(
        tmp_path, monkeypatch, missing_material_seal):
    cmp = setup(tmp_path)
    issued = issue(cmp)
    bind(cmp, monkeypatch, issued, read_fault='password' if missing_material_seal else None)
    result = execute(cmp)
    assert result.outcome is (M4Outcome.RECONCILIATION_REQUIRED if missing_material_seal else M4Outcome.SUCCEEDED)
    assert cmp['loader'].loads == cmp['execution'].claim_count == cmp['material'].claim_count == 1
    assert cmp['authority']._verified
    independent_recovery(cmp, tmp_path, monkeypatch)
    snapshot = {p.name: p.read_bytes() for p in cmp['directory'].iterdir()}
    grant = cmp['remove_authority'].issue(cmp['recovery'], **cmp['recovery_identity'])
    assert grant.plan.action_id == recovery_module.ACTION_ID
    assert grant.plan.plan_digest != issued.plan.plan_digest
    assert grant.authorization.requester_digest != grant.authorization.approver_digest
    with pytest.raises(M4AuthorizationDenied):
        cmp['remove_authority'].verify(grant.plan, grant.authorization, now_epoch=cmp['now'][0])
    assert not cmp['remove_authority']._consumed and cmp['remove_store'].claim_count == 0
    assert cmp['recovery'].execute(grant.plan, grant.authorization).outcome is M4Outcome.SUCCEEDED
    assert cmp['remove_source'].methods == ['DELETE', 'GET'] and len(cmp['remove_source'].requests) == 16
    assert cmp['remove_authority']._consumed and cmp['remove_store'].claim_count == 1
    assert cmp['loader'].loads == 1
    assert cmp['independent_custody'].inspect_original_creation() == cmp['original']
    assert all((cmp['directory'] / name).read_bytes() == value for name, value in snapshot.items())
    assert (cmp['directory'] / 'create.full-birth.json').exists() != missing_material_seal
    with pytest.raises(M4AuthorizationDenied):
        cmp['remove_authority'].issue(cmp['recovery'], **cmp['recovery_identity'])
    cmp['recovery'].close()
    cmp['remove_authority'].close()
    assert not cmp['authority']._key and not cmp['authority']._witness
    assert not cmp['remove_authority']._key and not cmp['remove_authority']._witness
    assert not cmp['recovery']._key


@pytest.mark.parametrize('fault', ['disabled', 'requester', 'transport', 'source', 'present', 'closed'])
def test_creation_requires_exact_lab_scope_identity_and_current_absence_before_material(tmp_path, fault):
    cmp = setup(tmp_path, enabled=fault != 'disabled')
    identity = dict(cmp['identity'])
    if fault in ('requester', 'transport'): identity[fault + '_digest'] = 'f' * 64
    if fault == 'source': cmp['available'][0] = False
    if fault == 'closed': cmp['authority'].close()
    current = a.windows_service_credential_state_digest(cmp['kwargs']['profile'], exists=fault == 'present')
    with pytest.raises(M4AuthorizationDenied): cmp['authority'].preview(current_digest=current, **identity)
    assert cmp['loader'].loads == cmp['execution'].claim_count == cmp['material'].claim_count == 0


@pytest.mark.parametrize('fault', ['key', 'witness', 'profile', 'namespace', 'source-callback', 'clock-callback', 'expiry'])
def test_grant_drift_refuses_before_material_or_http(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path)
    issued = issue(cmp)
    bind(cmp, monkeypatch, issued)
    if fault == 'key': (tmp_path / 'authority.key').write_bytes(b'z' * 32)
    if fault == 'witness': cmp['key'].write_bytes(b'z' * 32)
    if fault == 'profile': cmp['authority']._profile = replace(cmp['kwargs']['profile'], private_nonce='f' * 64)
    if fault == 'namespace': cmp['authority']._binding['scope_ref'] = 'other-scope'
    if fault == 'source-callback': cmp['authority']._source = lambda: True
    if fault == 'clock-callback': cmp['authority']._clock = lambda: 1000
    if fault == 'expiry': cmp['now'][0] = issued.authorization.expires_at
    with pytest.raises(M4AuthorizationDenied): execute(cmp)
    assert cmp['loader'].loads == cmp['material'].claim_count == 0 and not cmp['source'].requests


def test_create_requires_original_persistent_claim_and_rejects_other_profiles(tmp_path, monkeypatch):
    cmp = setup(tmp_path)
    issued = issue(cmp)
    with pytest.raises(M4AuthorizationDenied):
        cmp['authority'].verify(issued.plan, issued.authorization, now_epoch=1000)
    assert not cmp['authority']._verified and cmp['execution'].claim_count == 0
    with pytest.raises(M4AuthorizationDenied):
        a.WindowsServiceCredentialLabAuthority(**{**cmp['authority_kwargs'], 'profile': privileged_binding()})
    bind(cmp, monkeypatch, issued)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    before = len(cmp['source'].requests)
    assert execute(cmp).idempotent_replay
    assert len(cmp['source'].requests) == before == 8
    rebuilt = a.WindowsServiceCredentialLabAuthority(**cmp['authority_kwargs'])
    with pytest.raises(M4AuthorizationDenied):
        rebuilt.preview(current_digest=issued.plan.expected_current_digest, **cmp['identity'])


@pytest.mark.parametrize('fault', ['requester', 'transport', 'disabled', 'preclaimed-preview', 'closed'])
def test_recovery_scope_identity_or_closed_issuer_denies_without_current_material_reads(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path); bind(cmp, monkeypatch, issue(cmp)); assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    independent_recovery(cmp, tmp_path, monkeypatch)
    identity = dict(cmp['recovery_identity'])
    if fault in ('requester', 'transport'): identity[fault + '_digest'] = 'f' * 64
    if fault == 'disabled': cmp['remove_authority']._enabled = False
    if fault == 'preclaimed-preview': cmp['recovery'].preview()
    if fault == 'closed': cmp['remove_authority'].close()
    count = len(cmp['remove_source'].requests)
    with pytest.raises(M4AuthorizationDenied): cmp['remove_authority'].issue(cmp['recovery'], **identity)
    assert len(cmp['remove_source'].requests) == count and not cmp['remove_source'].methods
    assert cmp['remove_store'].claim_count == 0


def test_both_issuers_are_disabled_by_default_and_recovery_binding_refuses_before_io(tmp_path, monkeypatch):
    cmp = setup(tmp_path)
    options = {k: v for k, v in cmp['authority_kwargs'].items() if k != 'execution_enabled'}
    closed = a.WindowsServiceCredentialLabAuthority(**options)
    with pytest.raises(M4AuthorizationDenied):
        closed.preview(current_digest=a.windows_service_credential_state_digest(cmp['kwargs']['profile'], exists=False),
            **cmp['identity'])
    assert cmp['loader'].loads == cmp['execution'].claim_count == cmp['material'].claim_count == 0
    bind(cmp, monkeypatch, issue(cmp)); assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    independent_recovery(cmp, tmp_path, monkeypatch)
    options = {k: v for k, v in cmp['remove_authority_kwargs'].items() if k != 'execution_enabled'}
    disabled = ra.WindowsServiceCredentialRemovalLabAuthority(cmp['independent_custody'], **options)
    with pytest.raises(recovery_module.WindowsServiceCredentialRecoveryError):
        recovery_module.WindowsServiceCredentialRecovery(cmp['independent_custody'],
            **{**cmp['recovery_kwargs'], 'authorization_verifier': disabled})
    assert not cmp['remove_source'].requests and cmp['remove_store'].claim_count == 0
    closed.close(); disabled.close()


def test_creation_allows_clock_tick_inside_the_same_unexpired_persistent_claim(tmp_path, monkeypatch):
    cmp = setup(tmp_path)
    bind(cmp, monkeypatch, issue(cmp))
    verify = cmp['authority'].verify
    def after_tick(plan, authorization, *, now_epoch):
        cmp['now'][0] += 1
        verify(plan, authorization, now_epoch=now_epoch)
    monkeypatch.setattr(cmp['authority'], 'verify', after_tick)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    assert cmp['authority']._verified and len(cmp['source'].requests) == 8
    assert cmp['loader'].loads == cmp['execution'].claim_count == cmp['material'].claim_count == 1


@pytest.mark.parametrize('fault', ['key', 'witness', 'scope', 'preview', 'clock-callback', 'expiry'])
def test_recovery_issuer_or_grant_drift_stops_before_durable_claim_or_delete(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path); bind(cmp, monkeypatch, issue(cmp)); assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    independent_recovery(cmp, tmp_path, monkeypatch)
    grant = cmp['remove_authority'].issue(cmp['recovery'], **cmp['recovery_identity'])
    if fault == 'key': (tmp_path / 'remove-authority.key').write_bytes(b'z' * 32)
    if fault == 'witness': (tmp_path / 'remove-witness.key').write_bytes(b'z' * 32)
    if fault == 'scope': cmp['remove_authority']._binding['scope_ref'] = 'other-scope'
    if fault == 'preview': cmp['recovery']._preview = replace(cmp['recovery']._preview, expected_digest='f' * 64)
    if fault == 'clock-callback': cmp['remove_authority']._clock = lambda: 2000
    if fault == 'expiry': cmp['now'][0] = grant.authorization.expires_at
    with pytest.raises(recovery_module.WindowsServiceCredentialRecoveryError):
        cmp['recovery'].execute(grant.plan, grant.authorization)
    assert len(cmp['remove_source'].requests) == 7 and not cmp['remove_source'].methods
    assert cmp['remove_store'].claim_count == 0


def test_uncertain_delete_cannot_be_reauthorized_after_reconstruction(tmp_path, monkeypatch):
    cmp = setup(tmp_path); bind(cmp, monkeypatch, issue(cmp)); assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    independent_recovery(cmp, tmp_path, monkeypatch, fault='send')
    grant = cmp['remove_authority'].issue(cmp['recovery'], **cmp['recovery_identity'])
    assert cmp['recovery'].execute(grant.plan, grant.authorization).outcome is M4Outcome.RECONCILIATION_REQUIRED
    rebuilt = ra.WindowsServiceCredentialRemovalLabAuthority(cmp['independent_custody'], **cmp['remove_authority_kwargs'])
    runtime = recovery_module.WindowsServiceCredentialRecovery(cmp['independent_custody'],
        **{**cmp['recovery_kwargs'], 'authorization_verifier': rebuilt})
    count = len(cmp['remove_source'].requests)
    with pytest.raises(M4AuthorizationDenied): rebuilt.issue(runtime, **cmp['recovery_identity'])
    assert len(cmp['remove_source'].requests) == count and cmp['remove_source'].methods == ['DELETE']
    assert cmp['independent_custody'].inspect_original_creation() == cmp['original']


@pytest.mark.parametrize('key_family', ['creation', 'material', 'custody', 'recovery', 'witness'])
def test_independent_recovery_authority_rejects_reused_key_material(tmp_path, monkeypatch, key_family):
    cmp = setup(tmp_path); bind(cmp, monkeypatch, issue(cmp)); assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    independent_recovery(cmp, tmp_path, monkeypatch)
    values = dict(creation=cmp['execution']._key, material=cmp['material']._key,
        custody=cmp['independent_custody']._key, recovery=cmp['remove_store']._key, witness=b'w' * 32)
    (tmp_path / 'remove-authority.key').write_bytes(values[key_family])
    with pytest.raises(M4AuthorizationDenied):
        ra.WindowsServiceCredentialRemovalLabAuthority(cmp['independent_custody'], **cmp['remove_authority_kwargs'])
    assert not cmp['remove_source'].requests and cmp['remove_store'].claim_count == 0
