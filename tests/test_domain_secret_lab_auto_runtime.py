from dataclasses import replace

import pytest

from fortipam_mcp.onboarding_action_coordinator import OnboardingActionCoordinatorError
from fortipam_mcp.secret_create_lab_auto_runtime import (
    LabAutoSecretCreatePromoter, LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE,
)
from fortipam_mcp.domain_secret_projection_reader import (
    ADAPTER_REF, domain_secret_binding_digest, domain_secret_state_digest,
)
from fortipam_mcp.secret_onboarding_projection_source import secret_onboarding_projection_contract
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_domain_secret_projection_reader import planning_source, Transport
from test_secret_onboarding_action_sequence import _Services
from v4_planning import ChangeKind, ObjectClass, canonical_digest


def context():
    services = _Services()
    draft, source = planning_source(Transport())
    bound = replace(source._binding, requester_digest=services.requester.digest,
                    environment_ref=services.plan.environment_ref, scope_ref=services.plan.scope_ref)
    draft = replace(draft, environment_ref=bound.environment_ref, scope_ref=bound.scope_ref)
    line = replace(services.plan.lines[0], target_ref=bound.secret_object_ref,
                   target_class=ObjectClass.DOMAIN_SECRET_METADATA,
                   expected_current_digest=domain_secret_state_digest(bound.secret_object_ref, exists=False),
                   expected_state_digest=domain_secret_state_digest(bound.secret_object_ref, exists=True),
                   projection_contract_ref=secret_onboarding_projection_contract(ObjectClass.DOMAIN_SECRET_METADATA).contract_id)
    plan = replace(services.plan, lines=(line,), plan_digest=canonical_digest({
        **services.plan.canonical_content(), 'lines': [line.as_dict()],
    }))
    principal = V4PlanningPrincipal(services.requester, 'a' * 64)
    promoter = LabAutoSecretCreatePromoter(
        b'a' * 32, authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref, product_profile=LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE,
        domain_binding=bound,
    )
    return bound, draft, plan, principal, promoter


def test_domain_promotion_exact_private_binding_and_c3_request():
    bound, draft, plan, principal, promoter = context()
    artifact = promoter.promote(plan, plan.lines[0].line_ref, principal,
                               draft=draft, onboarding_binding=bound, now_epoch=plan.created_at + 1)
    assert artifact.plan.adapter_ref == ADAPTER_REF
    assert artifact.plan.parameters_digest == domain_secret_binding_digest(
        bound.create_binding, bound.secret_object_ref,
        dependency_refs=(bound.folder_object_ref, bound.target_object_ref, bound.template_object_ref, bound.secret_object_ref))
    assert artifact.lease_request.plan_digest == artifact.plan.plan_digest


@pytest.mark.parametrize('mode', ['binding', 'refs', 'class', 'contract', 'current', 'expected', 'update', 'dependency', 'objects', 'material'])
def test_domain_promotion_rejects_substitution(mode):
    bound, draft, plan, principal, promoter = context()
    if mode == 'binding':
        bound = replace(bound, create_binding=replace(bound.create_binding, secret_name='other-secret'))
    elif mode == 'refs':
        bound = replace(bound, folder_object_ref='other-folder-object-ref01')
    elif mode == 'objects':
        draft = replace(draft, desired_objects=draft.desired_objects[:-1])
    elif mode == 'material':
        draft = replace(draft, material_reference_metadata=replace(draft.material_reference_metadata, lifecycle='pending'))
    else:
        change = {'class': {'target_class': ObjectClass.SECRET_METADATA},
                  'contract': {'projection_contract_ref': 'other-contract'},
                  'current': {'expected_current_digest': 'a' * 64},
                  'expected': {'expected_state_digest': 'b' * 64},
                  'update': {'change_kind': ChangeKind.UPDATE},
                  'dependency': {'depends_on': ('other-line-ref01',)}}[mode]
        line = replace(plan.lines[0], **change)
        plan = replace(plan, lines=(line,), plan_digest=canonical_digest({**plan.canonical_content(), 'lines': [line.as_dict()]}))
    with pytest.raises(OnboardingActionCoordinatorError):
        promoter.promote(plan, plan.lines[0].line_ref, principal,
                         draft=draft, onboarding_binding=bound, now_epoch=plan.created_at + 1)


@pytest.mark.parametrize('profile, present', [('fortipam-191', True), (LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE, False)])
def test_domain_profile_requires_exact_binding(profile, present):
    bound, _, plan, _, _ = context()
    with pytest.raises(OnboardingActionCoordinatorError):
        LabAutoSecretCreatePromoter(b'a' * 32, authorized_environment_ref=plan.environment_ref,
                                   authorized_scope_ref=plan.scope_ref, product_profile=profile,
                                   domain_binding=bound if present else None)


@pytest.mark.parametrize('failure', [None, 'readback', 'owner', 'logout'])
@pytest.mark.parametrize('namespace_enabled', [False, True])
def test_domain_factory_c3_owner_readback_and_replay(tmp_path, monkeypatch, failure, namespace_enabled):
    from contextlib import contextmanager
    import json
    from fortipam_mcp import secret_create_lab_auto_runtime as module
    from fortipam_mcp import owner_domain_runtime as owner_module
    from fortipam_mcp import domain_secret_namespace_candidate as namespace_module
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_domain_secret_projection_reader import ABSENT, PRESENT
    from test_secret_create_191_http_transport import _Connection, _MetadataTransport
    from v4_planning import InMemoryM4ExecutionStateStore
    from v4_planning.material_runtime import InMemoryMaterialUseStateStore

    bound, draft, plan, principal, promoter = context()
    credentials = tmp_path / 'bindings.yaml'
    credentials.write_text('schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n')
    credentials.chmod(0o600)
    material = tmp_path / 'synthetic.env'
    material.write_text('FIXED_TEST_USERNAME=synthetic-user\nFIXED_TEST_PASSWORD=synthetic-password\n')
    material.chmod(0o600)
    events, bodies, buffers = [], [], []

    class Connection(_Connection):
        def request(self, method, path, body, headers):
            events.append('post')
            bodies.append((method, path, json.loads(bytes(body))))
            buffers.append(body.obj)

    class Owner(_MetadataTransport):
        @contextmanager
        def authenticated(self):
            events.append('login')
            if failure == 'owner':
                raise ValueError('Owner mismatch')
            try:
                yield self
            finally:
                events.append('logout')
                if failure == 'logout':
                    raise ValueError('Owner logout unavailable')

        def inspect_domain_account_projection(self, binding):
            assert binding.secret_name == bound.create_binding.secret_name
            events.append('read')
            return replace(PRESENT, metadata_verified=failure != 'readback') if bodies else ABSENT

        def verify_domain_account_preflight(self, target, address, domain, owner, **kwargs):
            events.append("preflight")
            assert (target, address, domain, owner) == (bound.create_binding.target_name, bound.create_binding.target_ipv4_address, bound.create_binding.domain_dns_root, bound.create_binding.target_owner_name)
            return True

        def secret_create_connection(self, *args, **kwargs):
            return Connection(*args, **kwargs)

    namespace_settings = None
    if namespace_enabled:
        pin = tmp_path / 'namespace-pin'; pin.write_text('synthetic'); pin.chmod(0o600)
        namespace_settings = namespace_module.DomainSecretNamespaceSettings(17, (51,52), 'example.test', 22, pin)

    def owner_transport(config, binding, credentials, *, allow_secret_create=False, namespace_settings=None):
        assert binding == bound.create_binding and allow_secret_create
        assert (namespace_settings is not None) is namespace_enabled
        return Owner()

    monkeypatch.setattr(namespace_module, 'owner_domain_namespace_transport', owner_transport)
    factory = module.FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=promoter, credential_bindings_path=credentials, secret_env_path=material,
        material_binding_ref='private-material-binding-ref01', credential_binding_id='fixed-secret-create',
        transport_config=SecretMetadataHttpTransportConfig('https://fortipam.example.test', 'test-token', 5, None),
        material_state_store=InMemoryMaterialUseStateStore(), execution_store=InMemoryM4ExecutionStateStore(),
        clock=lambda: plan.created_at + 1, owner_credentials=lambda: ('synthetic-owner', 'synthetic-password'),
        domain_namespace_settings=namespace_settings,
    )
    runner = factory.bind(plan, plan.lines[0].line_ref, principal, draft=draft, onboarding_binding=bound)
    assert events == []
    if failure in {'owner', 'logout'}:
        with pytest.raises(ValueError):
            runner.execute_bound()
    else:
        result = runner.execute_bound()
        assert (result['outcome'] == 'succeeded') is (failure is None)
    if failure == 'owner':
        assert events == ['login'] and not bodies
        return
    assert events == ['login', 'read', 'preflight', 'post', 'read', 'logout']
    assert bodies[0][0:2] == ('POST', '/api/v2/cmdb/secret/database')
    body = bodies[0][2]
    assert body['target'] == bound.create_binding.target_name
    assert body['field'] == [{'id': 0, 'name': 'Password', 'value': 'synthetic-password'},
                             {'id': 0, 'name': 'Username', 'value': 'synthetic-user'}]
    assert all(not any(buffer) for buffer in buffers)
    if failure != 'logout':
        runner.execute_bound()
        assert events.count('post') == 1


@pytest.mark.parametrize('mode', ['valid', 'missing_path', 'permissions', 'scope', 'owner_disabled'])
def test_domain_environment_exact_protected_binding(tmp_path, mode):
    from dataclasses import asdict
    import json
    from fortipam_mcp.secret_create_lab_auto_runtime import (
        LAB_AUTO_SECRET_CREATE_ENV_PREFIX, build_fortipam_191_lab_auto_secret_runner_factory,
    )
    bound, _, _, _, _ = context()
    payload = asdict(bound)
    private = payload.pop('create_binding')
    payload.update({key: private[key] for key in ('folder_path', 'secret_name', 'target_name',
        'target_ipv4_address', 'domain_dns_root', 'target_owner_name', 'target_classification_tag')})
    payload['contract'] = 'fortipam-700-domain-account-planning-binding-v1'
    path = tmp_path / 'domain.json'
    path.write_text(json.dumps(payload))
    path.chmod(0o644 if mode == 'permissions' else 0o600)
    config = {
        'PROFILE': LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE,
        'AUTHORIZED_ENVIRONMENT_REF': bound.environment_ref,
        'AUTHORIZED_SCOPE_REF': 'other-scope-ref01' if mode == 'scope' else bound.scope_ref,
        'DOMAIN_BINDING_FILE': str(path),
        'CREDENTIAL_BINDINGS_FILE': str(tmp_path / 'bindings.yaml'),
        'SECRET_ENV_FILE': str(tmp_path / 'unread-material.env'),
        'MATERIAL_BINDING_REF': 'private-material-binding-ref01',
        'CREDENTIAL_BINDING_ID': 'fixed-secret-create',
        'MATERIAL_STATE_DB': str(tmp_path / 'material.sqlite3'),
        'EXECUTION_STATE_DB': str(tmp_path / 'execution.sqlite3'),
        'OWNER_SESSION_ENABLED': 'false' if mode == 'owner_disabled' else 'true',
        'OWNER_LOGIN_ENV_FILE': str(tmp_path / 'unread-owner.env'),
        'OWNER_USERNAME_VARIABLE': 'SYNTHETIC_OWNER_USERNAME',
        'OWNER_PASSWORD_VARIABLE': 'SYNTHETIC_OWNER_PASSWORD',
    }
    if mode == 'missing_path':
        config.pop('DOMAIN_BINDING_FILE')
    for key, seed in (('AUTHORITY_KEY_FILE', b'a'), ('MATERIAL_STATE_HMAC_KEY_FILE', b'm'),
                      ('EXECUTION_STATE_HMAC_KEY_FILE', b'e')):
        key_path = tmp_path / (key + '.key')
        key_path.write_bytes(seed * 32)
        key_path.chmod(0o600)
        config[key] = str(key_path)
    env = {LAB_AUTO_SECRET_CREATE_ENV_PREFIX + key: value for key, value in config.items()}
    env.update({'FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED': 'true',
                'FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL': 'https://fortipam.example.test',
                'FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN': 'synthetic-token'})
    if mode == 'valid':
        factory = build_fortipam_191_lab_auto_secret_runner_factory(env)
        assert factory._promoter._domain_binding.secret_object_ref == bound.secret_object_ref
    else:
        with pytest.raises(OnboardingActionCoordinatorError):
            build_fortipam_191_lab_auto_secret_runner_factory(env)
    assert not (tmp_path / 'unread-owner.env').exists()
    assert not (tmp_path / 'unread-material.env').exists()
