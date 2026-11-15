from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from fortipam_mcp.owner_collector_runtime import PREFIX, owner_login_provider, OwnerAuthenticatedCollectorRuntime


def test_login_loader_is_lazy_exact_and_rejects_unprotected_or_linked_files(tmp_path):
    path = tmp_path / "login.env"
    env = {PREFIX + "SESSION_ENABLED": "true", PREFIX + "LOGIN_ENV_FILE": str(path),
        PREFIX + "USERNAME_VARIABLE": "GUI_USER", PREFIX + "PASSWORD_VARIABLE": "GUI_PASSWORD"}
    provider = owner_login_provider(env)
    assert provider is not None and not path.exists()
    with pytest.raises(ValueError, match="private collector Owner login"):
        provider()
    path.write_text("GUI_USER=gui-owner\nGUI_PASSWORD=synthetic-password\nWINDOWS_PASSWORD=unrelated-material\n")
    path.chmod(0o600)
    assert provider() == ("gui-owner", "synthetic-password")
    path.chmod(0o644)
    with pytest.raises(ValueError):
        provider()
    path.chmod(0o600)
    link = tmp_path / "linked.env"
    link.symlink_to(path)
    linked = owner_login_provider({**env, PREFIX + "LOGIN_ENV_FILE": str(link)})
    with pytest.raises(ValueError):
        linked()
    assert owner_login_provider({}) is None
    with pytest.raises(ValueError):
        owner_login_provider({PREFIX + "SESSION_ENABLED": "yes"})


@pytest.mark.parametrize("failure", [False, True])
def test_runtime_authenticates_only_for_execution_and_always_exits(failure):
    events = []
    @contextmanager
    def authenticated():
        events.append("login")
        try:
            yield
        finally:
            events.append("logout")
    def execute(reference, *, expected_onboarding_binding_digest):
        assert reference == "authorized" and expected_onboarding_binding_digest == "bound"
        assert events == ["login"]
        events.append("execute")
        if failure:
            raise RuntimeError("synthetic failure")
        return "result"
    runtime = SimpleNamespace(inspect_execution_plan=lambda _: "plan",
        inspect_onboarding_binding_digest=lambda _: "bound", execute_bound=execute)
    wrapped = OwnerAuthenticatedCollectorRuntime(runtime, SimpleNamespace(authenticated=authenticated))
    assert wrapped.inspect_execution_plan("authorized") == "plan"
    assert wrapped.inspect_onboarding_binding_digest("authorized") == "bound"
    assert events == []
    if failure:
        with pytest.raises(RuntimeError):
            wrapped.execute_bound("authorized", expected_onboarding_binding_digest="bound")
    else:
        assert wrapped.execute_bound("authorized", expected_onboarding_binding_digest="bound") == "result"
    assert events == ["login", "execute", "logout"]
