"""Service Target names cannot widen the retained Windows/Unix profiles."""
import json
import pytest
from fortipam_mcp import target_creation_serializer as s
from fortipam_mcp import target_creation_http_transport as t
from fortipam_mcp.target_creation_inputs import TargetCreationInputStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.target_contract import DEFAULT_TEMPLATE
from test_windows_execution_target_serializer import windows


def test_service_target_has_distinct_wire_custody_and_no_legacy_name_authority(tmp_path):
    _,proposal,expected=windows(name="mcp-v4-target-svc-20261031-r1")
    body=s.compile_service_account_target_request(proposal,bytearray(expected))
    assert json.loads(body)["winrm-https"]=="disable"
    witness=t._verify_request(body,proposal,bytearray(expected))
    root=tmp_path/"inputs";root.mkdir(mode=0o700)
    state=tmp_path/"state";state.mkdir(mode=0o700)
    store=TargetCreationInputStore(root)
    digest=store.provision(proposal,body,expected_material=expected)
    assert not any(body) and not any(expected)
    creator=store.open_creator(SecretMetadataHttpTransportConfig("https://pam.example","synthetic-token",5,None),
        input_digest=digest,state_directory=state,connection_factory=lambda *a,**k:pytest.fail("network"))
    assert creator._proposal==proposal and not creator._enabled
    assert json.loads((root/"inputs.verified.json").read_bytes())["serialization_digest"]==witness
    creator.close()
    for compiler in (s.compile_request,s.compile_windows_execution_target_request,s.compile_job_mapped_target_request):
        _,_,raw=windows(name=proposal.name)
        with pytest.raises(ValueError):compiler(proposal,raw)
        assert not any(raw)


@pytest.mark.parametrize("changes",[
    {"name":"MCPV4WinTarget20261031R1"},{"name":"mcp-v4-target-svc-20261031-r0"},
    {"domain":"example.test"},{"winrm-https":"enable"},{"gateway":"shared-gateway"},
])
def test_unqualified_service_target_refuses_and_erases(changes):
    _,proposal,raw=windows(**{"name":"mcp-v4-target-svc-20261031-r1",**changes})
    with pytest.raises(ValueError):s.compile_service_account_target_request(proposal,raw)
    assert not any(raw)


def test_reference_default_profile_does_not_relabel_or_replay_the_failed_v1(tmp_path):
    _,proposal,expected=windows(name="mcp-v4-target-svc-ref-20261031-r1",template=DEFAULT_TEMPLATE)
    body=s.compile_service_account_reference_target_request(proposal,bytearray(expected))
    assert json.loads(body)["template"]==DEFAULT_TEMPLATE
    assert t._verify_request(body,proposal,bytearray(expected))
    for compiler in (s.compile_service_account_target_request,s.compile_windows_execution_target_request):
        with pytest.raises(ValueError):compiler(proposal,bytearray(expected))
    _,old,old_expected=windows(name="mcp-v4-target-svc-20261031-r1")
    original=s.compile_service_account_target_request(old,bytearray(old_expected))
    assert t._verify_request(original,old,bytearray(old_expected))
    with pytest.raises(ValueError):s.compile_service_account_reference_target_request(old,old_expected)
    assert not any(old_expected)


@pytest.mark.parametrize("reference",[False,True])
@pytest.mark.parametrize("gate",["execution_enabled","recovery_enabled"])
def test_blocked_service_profile_stays_readonly_even_with_an_explicit_gate(tmp_path,reference,gate):
    name="mcp-v4-target-svc-ref-20261031-r1" if reference else "mcp-v4-target-svc-20261031-r1"
    _,proposal,expected=windows(name=name,template=DEFAULT_TEMPLATE if reference else "Windows Machine")
    compiler=s.compile_service_account_reference_target_request if reference else s.compile_service_account_target_request
    body=compiler(proposal,bytearray(expected))
    inputs=tmp_path/"inputs";inputs.mkdir(mode=0o700)
    state=tmp_path/"state";state.mkdir(mode=0o700)
    store=TargetCreationInputStore(inputs);digest=store.provision(proposal,body,expected_material=expected)
    original={p.name:p.read_bytes()for p in inputs.iterdir()if p.is_file()}
    with pytest.raises(ValueError):
        store.open_creator(SecretMetadataHttpTransportConfig("https://pam.example","synthetic-token",5,None),
            input_digest=digest,state_directory=state,connection_factory=lambda *a,**k:pytest.fail("network"),**{gate:True})
    assert original=={p.name:p.read_bytes()for p in inputs.iterdir()if p.is_file()}
    assert not list(state.iterdir())
