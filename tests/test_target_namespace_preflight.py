"""Actual reader composition with synthetic HTTP and bounded SSH results."""
from dataclasses import replace
import pytest

from fortipam_mcp import target_namespace_preflight as p
from fortipam_mcp.target_qualified_namespace_reader import FortiPamTargetQualifiedNamespaceReader
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_target_api_names_reader import NamesHarness, COORDINATES, DIGEST

NAME = 'mcp-v4-target-synthetic'


class BracketHarness(NamesHarness):
    def handle(self, request):
        if request.url.params.get('format') == 'name':
            return super().handle(request)
        # The original synthetic dependency harness indexes its eight reads.
        saved = self.requests
        self.requests = [r for r in saved if r.url.params.get('format') != 'name']
        try:
            response = super().handle(request)
            last = self.requests[-1]
        finally:
            self.requests = saved
        self.requests.append(last)
        return response


@pytest.fixture
def setup(tmp_path, monkeypatch):
    h = BracketHarness(); api = h.reader()
    pin = tmp_path/'known_hosts'; pin.write_text('synthetic pin\n'); pin.chmod(0o600)
    config = TargetSshTransportConfig('synthetic.invalid', 22, 'synthetic', 'synthetic', pin, 10)
    ssh_now = [1000.0]
    namespace = FortiPamTargetQualifiedNamespaceReader(config, serial_digest=DIGEST, clock=lambda:ssh_now[0])
    calls = []
    async def read(witnesses):
        calls.append(witnesses)
        return witnesses + ('Hidden Target',)
    monkeypatch.setattr(namespace, '_bounded_read', read)
    return h, api, namespace, ssh_now, calls, p.TargetNamespacePreflight(api, namespace)


def test_actual_fresh_brackets_and_opaque_result(setup):
    h, api, namespace, clock, calls, joined = setup
    observed = joined.observe(NAME, COORDINATES)
    joined.check_current(observed, candidate_name=NAME)
    assert len(h.requests) == 20 and calls == [('Synthetic A', 'Synthetic B')]
    assert observed.candidate_absent and observed.target_count == 3
    assert observed.source_context_digest == api._source
    assert observed.api_witness_digest == namespace._current.api_witness_digest
    assert not hasattr(observed, 'names') and 'Synthetic' not in repr(observed)
    assert all(client.is_closed for client in h.clients)


@pytest.mark.parametrize('fault', ['copied', 'candidate', 'api_expired', 'ssh_expired',
    'api_replaced', 'names_replaced', 'ssh_replaced', 'closed', 'api_closed', 'ssh_closed', 'source'])
def test_current_requires_all_original_evidence(setup, fault):
    h, api, namespace, clock, calls, joined = setup
    value = joined.observe(NAME, COORDINATES); candidate = NAME
    if fault == 'copied': value = replace(value)
    if fault == 'candidate': candidate += '2'
    if fault == 'api_expired': h.now = 40
    if fault == 'ssh_expired': clock[0] = 1010
    if fault == 'api_replaced': api.observe(COORDINATES)
    if fault == 'names_replaced': api.observe_names(api._current)
    if fault == 'ssh_replaced': namespace.read_namespace(NAME, api_names=('Synthetic A', 'Synthetic B'))
    if fault == 'closed': joined.close()
    if fault == 'api_closed': api.close()
    if fault == 'ssh_closed': namespace.close()
    if fault == 'source': api._source = 'b'*64
    with pytest.raises(p.TargetNamespacePreflightError): joined.check_current(value, candidate_name=candidate)


@pytest.mark.parametrize('fault', ['dependency_drift', 'names_drift', 'api_timeout', 'ssh_timeout', 'ssh_error'])
def test_bracket_failure_returns_no_partial_evidence(setup, monkeypatch, fault):
    h, api, namespace, clock, calls, joined = setup
    prior = joined.observe(NAME, COORDINATES)
    original = namespace._bounded_read
    async def read(witnesses):
        result = await original(witnesses)
        if fault == 'dependency_drift':
            h.values[1]['results']['extra'] = 'changed'; h.values[6]['results']['extra'] = 'changed'
        if fault == 'names_drift':
            original_handle = h.handle
            def changed(request):
                result = original_handle(request)
                if request.url.params.get('format') == 'name':
                    import httpx
                    content = result.read().replace(b'Synthetic B', b'Synthetic C')
                    result.close()
                    from test_target_api_dependency_reader import Body
                    return httpx.Response(200, headers={'content-type':'application/json'}, stream=Body(content))
                return result
            h.handle = changed
        if fault == 'api_timeout': h.now = 40
        if fault == 'ssh_timeout': clock[0] = 1010
        if fault == 'ssh_error': raise RuntimeError('PRIVATE_SENTINEL')
        return result
    monkeypatch.setattr(namespace, '_bounded_read', read)
    with pytest.raises(p.TargetNamespacePreflightError) as error: joined.observe(NAME, COORDINATES)
    assert str(error.value) == p._ERROR
    with pytest.raises(p.TargetNamespacePreflightError): joined.check_current(prior, candidate_name=NAME)


def test_source_mismatch_denied_before_network(setup):
    h, api, namespace, clock, calls, joined = setup
    namespace._serial = 'b'*64
    with pytest.raises(p.TargetNamespacePreflightError): p.TargetNamespacePreflight(api, namespace)
    with pytest.raises(p.TargetNamespacePreflightError): joined.observe(NAME, COORDINATES)
    assert not h.requests and not calls


def test_collision_is_evidence_not_write_authority(setup, monkeypatch):
    h, api, namespace, clock, calls, joined = setup
    async def read(witnesses): return witnesses + (NAME.upper(),)
    monkeypatch.setattr(namespace, '_bounded_read', read)
    observed = joined.observe(NAME, COORDINATES)
    assert not observed.candidate_absent
    with pytest.raises(p.TargetNamespacePreflightError):
        joined.check_transport_source(observed, candidate_name=NAME, transport=object())

from test_target_source_binding import sources


@pytest.mark.parametrize('kind', ['creator', 'coordinate'])
def test_actual_adapter_source_binding(setup, sources, kind):
    h, old_api, namespace, clock, calls, unused = setup
    _, make_reader, make_adapter, _, _ = sources
    prototype = make_reader()
    api = p.TargetApiDependencyReader(prototype._config, serial_digest=DIGEST,
        clock=lambda:h.now, client_factory=h.factory)
    prototype.close()
    joined = p.TargetNamespacePreflight(api, namespace)
    observed = joined.observe(NAME, COORDINATES)
    transport = make_adapter(kind)
    joined.check_transport_source(observed, candidate_name=NAME, transport=transport)
    assert not transport._enabled
    wrong = make_adapter(kind, bearer_token='other-synthetic-token')
    with pytest.raises(p.TargetNamespacePreflightError):
        joined.check_transport_source(observed, candidate_name=NAME, transport=wrong)
