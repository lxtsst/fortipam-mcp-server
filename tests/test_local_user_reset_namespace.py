"""Fixed two-table global projections do not inherit actor-visible completeness."""
import pytest

from fortipam_mcp import local_user_reset_namespace as module
from test_folder_namespace_ssh_reader import Peer as BasePeer, config, frame

CANDIDATE = "mcp-v4-user-reset-new-fixture"
ADMIN = "synthetic-global-owner"
API = "synthetic-api-principal"
ADMIN_PROMPT = b"FPA-SYNTHETIC (admin) #"
API_PROMPT = b"FPA-SYNTHETIC (api-user) #"


def names_frame(names, prompt):
    return frame(module._NAME_PROJECTION, [b'    edit "' + name.encode() + b'"' for name in names], prompt)


class Peer(BasePeer):
    def __init__(self):
        super().__init__()
        self.rows = {"admin": (ADMIN, "Unlisted user"), "api-user": (API,)}
        self.contexts = {"admin": ADMIN_PROMPT, "api-user": API_PROMPT}
        self.table = None
        self.reads = {"admin": 0, "api-user": 0}
        self.second = {}
        self.hook = lambda:None

    async def read(self, process, command, prompt, deadline):
        if command in (module._SERIAL_COMMAND, module._VERSION_COMMAND):
            return await super().read(process, command, prompt, deadline)
        assert process is self and command == module._NAME_PROJECTION and prompt == self.contexts[self.table]
        self.commands.append(command); self.reads[self.table] += 1
        self.hook()
        if self.reads[self.table] == 2 and self.table in self.second: return self.second[self.table]
        return names_frame(self.rows[self.table], prompt)

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root
        self.commands.append(command)
        if command == "end": return self.returned
        assert command in ("config system admin", "config system api-user")
        self.table = command.rsplit(" ",1)[-1]
        return self.contexts[self.table]


@pytest.fixture
def peer(monkeypatch, config):
    peer = Peer(); peer._config = config
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config:peer)
    monkeypatch.setattr(module, "_send_and_read", peer.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", peer.dynamic)
    monkeypatch.setattr(module, "_close_cli", peer.close)
    return peer


def reader(config, **changes):
    args = dict(candidate_name=CANDIDATE, admin_witness=ADMIN, api_witness=API,
        expected_serial="SYNTHETIC_SERIAL", before_send=lambda:None)
    return module.LocalResetNamespaceReader(config, **(args | changes))


@pytest.mark.parametrize("collision", [None, "admin", "api-user"])
def test_same_global_owner_and_api_controls_cover_both_tables(config, peer, collision):
    if collision is not None: peer.rows[collision] += (CANDIDATE.upper(),)
    source = reader(config); observed = source.read_namespace()
    assert observed.global_name_absent is (collision is None)
    assert observed.candidate_admin_occurrences == int(collision == "admin")
    assert observed.candidate_api_occurrences == int(collision == "api-user")
    assert source._admin_names == peer.rows["admin"] and source._api_names == peer.rows["api-user"]
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND,
        "config system admin", module._NAME_PROJECTION, module._NAME_PROJECTION, "end",
        "config system api-user", module._NAME_PROJECTION, module._NAME_PROJECTION, "end"]
    assert peer.closed == peer.connection_closed == 1 and CANDIDATE not in repr(observed)
    with pytest.raises(ValueError): source.read_namespace()
    assert peer.connection_closed == 1 and not source._admin_names and not source._api_names


@pytest.mark.parametrize("fault", ["missing-admin", "missing-api", "duplicate", "drift", "extra-output", "serial", "context", "exit", "source", "guard", "close"])
def test_bad_frames_visibility_identity_drift_or_close_never_prove_absence(config, peer, fault):
    gate = [True]
    def guard():
        if not gate[0]: raise ValueError
    source = reader(config, before_send=guard)
    if fault == "missing-admin": peer.rows["admin"] = ("Other",)
    if fault == "missing-api": peer.rows["api-user"] = ("Other",)
    if fault == "duplicate": peer.rows["api-user"] += (API.upper(),)
    if fault == "drift": peer.second["api-user"] = names_frame((API, "changed"), API_PROMPT)
    if fault == "extra-output": peer.second["admin"] = frame(module._NAME_PROJECTION, [b'    set password "SENSITIVE"'], ADMIN_PROMPT)
    if fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: FOREIGN"])
    if fault == "context": peer.contexts["api-user"] = ADMIN_PROMPT
    if fault == "exit": peer.returned = b"OTHER #"
    if fault == "source": peer.hook = lambda:config.known_hosts_file.write_text("changed")
    if fault == "guard": peer.hook = lambda:gate.__setitem__(0,False)
    if fault == "close": peer.close_error = True
    with pytest.raises(ValueError) as caught: source.read_namespace()
    assert str(caught.value) == module._ERROR and source._closed
    assert not source._admin_names and not source._api_names
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("changes", [{"candidate_name":"arbitrary"}, {"admin_witness":CANDIDATE},
    {"api_witness":"bad\nname"}, {"expected_serial":"bad serial"}, {"before_send":None}])
def test_invalid_private_binding_stops_before_ssh(config, peer, changes):
    with pytest.raises(ValueError): reader(config, **changes)
    assert not peer.commands and not peer.connection_closed
