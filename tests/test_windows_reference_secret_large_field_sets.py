"""Native-size field sets across original birth and independent readback."""
import importlib

import pytest

from fortipam_mcp import windows_privileged_secret_birth as b
from test_windows_privileged_secret_birth import raw, witnesses
from v4_planning import M4Outcome, canonical_digest


@pytest.mark.parametrize("profile", ["service", "privileged"])
@pytest.mark.parametrize("field_count", [124, 512])
@pytest.mark.parametrize("current_change", [None, "added", "removed"])
def test_complete_native_size_birth_preserves_every_field_and_independent_recovery_evidence(
        tmp_path, monkeypatch, profile, field_count, current_change):
    module = importlib.import_module("test_windows_service_credential_lifecycle" if profile == "service"
        else "test_windows_privileged_secret_birth")
    function = "postcondition" if profile == "service" else "full_row"
    original = getattr(module, function)
    def full_row():
        value = original()
        fields = value["results"]
        for index in range(field_count - len(fields)):
            fields[f"native-extra-{index:03}"] = "OPAQUE_LARGE_ROW_SENTINEL"
        assert len(fields) == field_count
        return value
    monkeypatch.setattr(module, function, full_row)
    cmp = module.fixture(tmp_path)
    assert module.execute(cmp).outcome is M4Outcome.SUCCEEDED
    custody = cmp["custody"]
    birth = custody.inspect_original_creation()
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    assert b._FRAME in snapshot and b._BIRTH in snapshot
    assert b"OPAQUE_LARGE_ROW_SENTINEL" not in b"".join(snapshot.values())
    assert cmp["loader"].loads == cmp["peer"].calls == 1
    assert module.execute(cmp).idempotent_replay and cmp["peer"].calls == 1
    custody.close()
    independent = type(custody)(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    assert independent.inspect_original_creation() == birth
    first, last = full_row(), full_row()
    if current_change is not None:
        for value in (first, last):
            if current_change == "added": value["results"]["late-extra"] = "OPAQUE_LARGE_ROW_SENTINEL"
            else: del value["results"]["native-extra-000"]
    before, after = raw(first), raw(last)
    if current_change is None:
        assert independent.consume_pristine_birth(before, after, **witnesses(independent)) == birth
    else:
        with pytest.raises(b.WindowsPrivilegedSecretBirthError):
            independent.consume_pristine_birth(before, after, **witnesses(independent))
    assert not before and not after
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    independent.close()


def test_existing_small_field_set_digest_is_unchanged():
    names = frozenset(f"field-{index:02}" for index in range(64))
    assert b._row_field_set_digest(names) == canonical_digest(sorted(names))


def test_small_schema_minimum_keeps_its_digest_when_first_runtime_frame_has_124_fields(tmp_path, monkeypatch):
    module = importlib.import_module("test_windows_service_credential_lifecycle")
    cmp = module.fixture(tmp_path)
    custody = cmp["custody"]
    assert len(custody._row_fields) <= 64
    minimum_digest = canonical_digest(sorted(custody._row_fields))
    original = module.postcondition
    def full_row():
        value = original()
        for index in range(124 - len(value["results"])):
            value["results"][f"runtime-extra-{index:03}"] = "OPAQUE_RUNTIME_SENTINEL"
        return value
    monkeypatch.setattr(module, "postcondition", full_row)
    assert module.execute(cmp).outcome is M4Outcome.SUCCEEDED
    assert custody._row_fields_digest == minimum_digest
    birth = custody.inspect_original_creation()
    first, last = raw(full_row()), raw(full_row())
    assert custody.consume_pristine_birth(first, last, **witnesses(custody)) == birth
    assert not first and not last
    custody.close()
