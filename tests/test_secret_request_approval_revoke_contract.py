from copy import deepcopy
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from fortipam_mcp.secret_request_approval_revoke_contract import (
    SecretRequestApprovalRevokeContractError,
    SecretRequestApprovalRevokeNativeTierWitness,
    compile_secret_request_approval_revoke_body,
    qualify_secret_request_approval_revoke_native_tiers,
    secret_request_approval_revoke_url,
    secret_request_approval_revoke_launcher_window_available,
    single_reviewer_frontend_approval_revoke_eligible,
)
from fortipam_mcp.secret_metadata_http_transport import MAX_RESPONSE_BYTES

_ROOT = Path(__file__).resolve().parents[1]
_ASSET = _ROOT / ".codex_tmp/bp008-checkout-r1/checkout_main_current.js"
_SHA256 = "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"
_NODE = shutil.which("node")


@pytest.mark.skipif(not _ASSET.is_file() or _NODE is None,
                    reason="Retained frontend asset and Node are needed for source alignment.")
def test_two_field_body_matches_actual_cached_frontend_serializer() -> None:
    asset = _ASSET.read_bytes()
    assert hashlib.sha256(asset).hexdigest() == _SHA256
    source = asset.decode("utf-8")
    start = source.index("buildSecretRequestPayload(A,V,j,U,H,$,X,re){")
    assert start == 364398
    end = source.index("submitApproval(A,V,j,U,H,$,X,re){", start)
    method = source[start:end]
    # Only the async-generator helper is replaced. The real method executes.
    script = r"""
const i = {A: generator => function (...args) {
    const iterator = generator.apply(this, args);
    function advance(method, value) {
        let result;
        try { result = iterator[method](value); }
        catch (error) { return Promise.reject(error); }
        return result.done ? Promise.resolve(result.value)
            : Promise.resolve(result.value).then(
                value => advance('next', value), error => advance('throw', error));
    }
    return advance('next');
}};
const actual = new (class { METHOD })();
actual.buildSecretRequestPayload(19, 1).then(body => {
    if (Object.keys(body).length !== 8) throw new Error('Unexpected source shape');
    process.stdout.write(JSON.stringify(body));
});
""".replace("METHOD", method)
    assert _NODE is not None
    result = subprocess.run([_NODE, "-e", script], capture_output=True, text=True,
                            check=True, timeout=10)
    assert json.loads(result.stdout) == compile_secret_request_approval_revoke_body(request_id=19)
    assert secret_request_approval_revoke_url(19) == "/api/v2/internal/request-review/19"
    assert 'const y="/api/v2/internal"' in source
    assert "deleteApproval(A,V){" in source
    assert '`${y}/request-review/${A}`,H={body:yield j.buildSecretRequestPayload(A,V)}' in source
    assert "return j.delete(U,()=>{},H,!0)" in source


@pytest.mark.parametrize("request_id", [0, -1, 2_147_483_648, True, False, "19", 19.0, None])
def test_serializer_and_url_refuse_non_integer_or_out_of_bounds_ids(request_id: Any) -> None:
    with pytest.raises(SecretRequestApprovalRevokeContractError):
        compile_secret_request_approval_revoke_body(request_id=request_id)
    with pytest.raises(SecretRequestApprovalRevokeContractError):
        secret_request_approval_revoke_url(request_id)


@pytest.mark.parametrize("tier", [0, 2, 3, True, False, "1", 1.0, None])
def test_first_profile_refuses_other_tiers_and_boolean_tier(tier: Any) -> None:
    with pytest.raises(SecretRequestApprovalRevokeContractError):
        compile_secret_request_approval_revoke_body(request_id=19, tier=tier)


@pytest.mark.parametrize("failure", [None, "self", "foreign", "pending", "denied",
                                    "duplicate", "tier2", "tier3", "missing", "unknown",
                                    "entry_extra", "bad_name", "boolean_name", "surrogate", "bad_status",
                                    "tuple", "full_native_model"])
def test_eligibility_is_only_one_owned_approved_tier_projection(failure: str | None) -> None:
    tiers: dict[str, Any] = {
        "tier1": [{"name": "synthetic-reviewer", "status": "approved"}],
        "tier2": [], "tier3": [],
    }
    requester, reviewer = "synthetic-requester", "synthetic-reviewer"
    if failure == "self": requester = reviewer
    if failure == "foreign": reviewer = "other-reviewer"
    if failure in {"pending", "denied"}: tiers["tier1"][0]["status"] = failure
    if failure == "duplicate": tiers["tier1"].append(deepcopy(tiers["tier1"][0]))
    if failure in {"tier2", "tier3"}: tiers[failure] = deepcopy(tiers["tier1"])
    if failure == "missing": del tiers["tier3"]
    if failure == "unknown": tiers["tier4"] = []
    if failure == "entry_extra": tiers["tier1"][0]["extra"] = "unknown"
    if failure == "bad_name": tiers["tier1"][0]["name"] = "synthetic-reviewer\n"
    if failure == "boolean_name": tiers["tier1"][0]["name"] = True
    if failure == "surrogate": tiers["tier1"][0]["name"] = "synthetic-reviewer\ud800"
    if failure == "bad_status": tiers["tier1"][0]["status"] = "revoked"
    if failure == "tuple": tiers["tier1"] = tuple(tiers["tier1"])
    if failure == "full_native_model": tiers.update({"id": 19, "request-type": "launcher"})
    snapshot = deepcopy(tiers)
    assert single_reviewer_frontend_approval_revoke_eligible(
        tiers, requester=requester, authenticated_reviewer=reviewer,
    ) is (failure is None)
    assert tiers == snapshot


def test_projection_eligibility_does_not_admit_a_request_or_bind_a_secret_profile() -> None:
    # There is deliberately no native detail, type, ID, Profile, window or auth input.
    assert compile_secret_request_approval_revoke_body(request_id=2_147_483_647) == {
        "request-id": 2_147_483_647, "tier": 1,
    }
    assert not single_reviewer_frontend_approval_revoke_eligible(
        {"tier1": [{"Name": "synthetic-reviewer", "status": "approved"}], "tier2": [], "tier3": []},
        requester="synthetic-requester", authenticated_reviewer="synthetic-reviewer",
    )


def _native_tiers() -> dict[str, Any]:
    return {
        "tier1": [{"name": "synthetic-reviewer", "q_origin_key": "synthetic-reviewer",
                   "status": "approved", "comments": "synthetic preserved comment",
                   "update-time": "opaque-not-a-date"}],
        "tier2": [], "tier3": [],
    }


def _qualify_native(tiers: object, *, requester: str = "synthetic-requester",
                    reviewer: str = "synthetic-reviewer") -> SecretRequestApprovalRevokeNativeTierWitness:
    return qualify_secret_request_approval_revoke_native_tiers(
        tiers, requester=requester, authenticated_reviewer=reviewer,
    )


def test_native_tier_witness_pins_owned_identity_and_all_opaque_preservation() -> None:
    tiers = _native_tiers()
    snapshot = deepcopy(tiers)
    witness = _qualify_native(tiers)
    expected = hashlib.sha256(json.dumps(
        tiers, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()
    assert witness.private_digest == expected
    assert [field.name for field in fields(witness)] == ["private_digest"]
    assert witness.private_digest not in repr(witness)
    assert "synthetic-reviewer" not in repr(witness)
    assert tiers == snapshot
    reordered = {key: tiers[key] for key in ("tier3", "tier1", "tier2")}
    assert _qualify_native(reordered).private_digest == expected
    for member in ("comments", "update-time"):
        changed = deepcopy(tiers)
        changed["tier1"][0][member] += " drift"
        assert _qualify_native(changed).private_digest != expected
    # Opaque data is preserved without date interpretation or text trimming.
    tiers["tier1"][0]["comments"] = " \nsynthetic opaque text\n "
    tiers["tier1"][0]["update-time"] = ""
    assert _qualify_native(tiers).private_digest != expected
    # The narrower frontend projection predicate remains distinct.
    assert not single_reviewer_frontend_approval_revoke_eligible(
        tiers, requester="synthetic-requester", authenticated_reviewer="synthetic-reviewer",
    )


@pytest.mark.parametrize("failure", ["self", "foreign", "name", "origin", "pending",
                                    "duplicate", "tier2", "tier3", "missing_tier", "extra_tier",
                                    "extra_member", "missing_member", "boolean_name", "boolean_origin", "boolean_status",
                                    "boolean_comments", "boolean_time", "surrogate_name", "surrogate_origin", "surrogate_comments",
                                    "surrogate_time", "long_name", "long_origin", "long_comments", "long_time", "tuple"])
def test_native_tier_qualifier_refuses_unqualified_grammar_or_identity(failure: str) -> None:
    tiers = _native_tiers()
    row = tiers["tier1"][0]
    requester, reviewer = "synthetic-requester", "synthetic-reviewer"
    if failure == "self": requester = reviewer
    if failure == "foreign": reviewer = "other-reviewer"
    if failure == "name": row["name"] = "other-reviewer"
    if failure == "origin": row["q_origin_key"] = "other-reviewer"
    if failure == "pending": row["status"] = "pending"
    if failure == "duplicate": tiers["tier1"].append(deepcopy(row))
    if failure in {"tier2", "tier3"}: tiers[failure] = [deepcopy(row)]
    if failure == "missing_tier": del tiers["tier3"]
    if failure == "extra_tier": tiers["tier4"] = []
    if failure == "extra_member": row["unknown"] = "unqualified"
    if failure == "missing_member": del row["update-time"]
    for kind, member in (("name", "name"), ("origin", "q_origin_key"), ("status", "status"),
                         ("comments", "comments"), ("time", "update-time")):
        if failure == "boolean_" + kind: row[member] = True
        if failure == "surrogate_" + kind: row[member] = "invalid\ud800"
        if failure == "long_" + kind:
            row[member] = "界" * (MAX_RESPONSE_BYTES // 3 + 1 if kind in {"comments", "time"} else 86)
    if failure == "tuple": tiers["tier1"] = tuple(tiers["tier1"])
    with pytest.raises(SecretRequestApprovalRevokeContractError,
                       match="^The fixed Launcher Request approval withdrawal is unavailable.$"):
        _qualify_native(tiers, requester=requester, reviewer=reviewer)


@pytest.mark.parametrize("member", ["comments", "update-time"])
def test_native_tier_opaque_utf8_bound_uses_existing_response_budget(member: str) -> None:
    tiers = _native_tiers()
    # The pure tier qualifier does not impose the old, unsupported 255-byte cap.
    tiers["tier1"][0][member] = "界" * 100
    witness = _qualify_native(tiers)
    exact_budget = "界" * (MAX_RESPONSE_BYTES // 3) + "a" * (MAX_RESPONSE_BYTES % 3)
    assert len(exact_budget.encode("utf-8")) == MAX_RESPONSE_BYTES
    tiers["tier1"][0][member] = exact_budget
    assert _qualify_native(tiers).private_digest != witness.private_digest
    tiers["tier1"][0][member] += "a"
    with pytest.raises(SecretRequestApprovalRevokeContractError):
        _qualify_native(tiers)
    # A complete reader separately bounds the enclosing native JSON response.


@pytest.mark.parametrize("update_time", [0, 1, -1, 9_007_199_254_740_991, -9_007_199_254_740_991])
def test_native_tier_integer_update_time_preserves_value_and_original_type(update_time: int) -> None:
    tiers = _native_tiers()
    tiers["tier1"][0]["update-time"] = update_time
    snapshot = deepcopy(tiers)
    witness = _qualify_native(tiers)
    canonical = json.dumps(tiers, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert witness.private_digest == hashlib.sha256(canonical).hexdigest()
    assert tiers == snapshot
    tiers["tier1"][0]["update-time"] = str(update_time)
    assert _qualify_native(tiers).private_digest != witness.private_digest
    tiers["tier1"][0]["update-time"] = update_time - 1 if update_time > 0 else update_time + 1
    assert _qualify_native(tiers).private_digest != witness.private_digest


@pytest.mark.parametrize("update_time", [True, False, 9_007_199_254_740_992,
                                        -9_007_199_254_740_992, 1.0, None])
def test_native_tier_integer_update_time_refuses_booleans_unsafe_or_other_types(update_time: Any) -> None:
    tiers = _native_tiers()
    tiers["tier1"][0]["update-time"] = update_time
    with pytest.raises(SecretRequestApprovalRevokeContractError):
        _qualify_native(tiers)


_WINDOW_NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)


class _WindowClock(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> "_WindowClock":
        clock = cls.fromtimestamp(_WINDOW_NOW.timestamp(), tz=timezone.utc)
        return clock.astimezone(tz) if tz is not None else clock.replace(tzinfo=None)


@pytest.mark.skipif(not _ASSET.is_file() or _NODE is None,
                    reason="Retained frontend asset and Node are needed for source alignment.")
def test_launcher_window_matches_actual_frontend_seconds_converter(monkeypatch: pytest.MonkeyPatch) -> None:
    asset = _ASSET.read_bytes()
    assert hashlib.sha256(asset).hexdigest() == _SHA256
    source = asset.decode("utf-8")
    start = source.index("convertCmdbTzToDisplayTz(C){")
    assert start == 1885086
    method = source[start:source.index("convertDisplayTzToCmdbTz(C,A,V){", start)]
    constants_start = source.index('x=function(O){return O[O.Seconds=0]="Seconds"')
    constants = source[constants_start:source.index(",D=function(O)", constants_start)]
    assert source.index("SToMs=1e3") == 1880214
    epoch_start, epoch_end = int(_WINDOW_NOW.timestamp()) - 600, int(_WINDOW_NOW.timestamp()) + 600
    script = r"""
const i = {A: generator => async function (...args) {
    const iterator = generator.apply(this, args);
    let step = iterator.next();
    while (!step.done) step = iterator.next(await step.value);
    return step.value;
}};
var CONSTANTS;
const calls = [];
const actual = new (class {
    METHOD
    convertUTCToTZDeviceAwareDate(milliseconds) {
        calls.push(milliseconds);
        return new Date(milliseconds);
    }
    formateDateToText(date) {
        return new Intl.DateTimeFormat('sv-SE', {timeZone: 'Asia/Shanghai',
            year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit',
            minute: '2-digit', second: '2-digit', hour12: false}).format(date);
    }
})();
Promise.all(TIMES.map(value => actual.convertCmdbTzToDisplayTz(value)))
    .then(values => process.stdout.write(JSON.stringify({calls, values})));
""".replace("CONSTANTS", constants).replace("METHOD", method).replace(
        "TIMES", json.dumps([epoch_start, epoch_end]),
    )
    assert _NODE is not None
    result = subprocess.run([_NODE, "-e", script], capture_output=True, text=True,
                            check=True, timeout=10)
    actual = json.loads(result.stdout)
    assert actual["calls"] == [epoch_start * 1000, epoch_end * 1000]
    shanghai = timezone(timedelta(hours=8))
    expected = [datetime.fromtimestamp(value, timezone.utc).astimezone(shanghai).strftime(
        "%Y-%m-%d %H:%M:%S",
    ) for value in (epoch_start, epoch_end)]
    assert actual["values"] == expected
    monkeypatch.setattr("fortipam_mcp.secret_request_http_transport.datetime", _WindowClock)
    assert secret_request_approval_revoke_launcher_window_available(
        {"start-time": epoch_start, "expiration-time": epoch_end, "timezone": "Asia/Shanghai"},
        server_time=_WINDOW_NOW,
    )
    assert secret_request_approval_revoke_launcher_window_available(
        {"start-time": expected[0], "expiration-time": expected[1], "timezone": "Asia/Shanghai"},
        server_time=_WINDOW_NOW,
    )


@pytest.mark.parametrize("failure", ["boolean_start", "boolean_end", "zero", "negative", "unsafe",
                                    "out_of_date_range", "float", "equal", "reversed", "future", "expired",
                                    "timezone", "malformed_string", "absent_date", "naive_date", "stale_date",
                                    "future_date", "pending_full_record"])
def test_launcher_window_refuses_unqualified_times_or_device_clock(
    failure: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("fortipam_mcp.secret_request_http_transport.datetime", _WindowClock)
    epoch = int(_WINDOW_NOW.timestamp())
    window: dict[str, Any] = {"start-time": epoch - 600, "expiration-time": epoch + 600,
                              "timezone": "Asia/Shanghai"}
    date: datetime | None = _WINDOW_NOW
    if failure == "boolean_start": window["start-time"] = True
    if failure == "boolean_end": window["expiration-time"] = False
    if failure == "zero": window["start-time"] = 0
    if failure == "negative": window["start-time"] = -1
    if failure == "unsafe": window["start-time"] = 9_007_199_254_740_992
    if failure == "out_of_date_range": window["expiration-time"] = 9_007_199_254_740_991
    if failure == "float": window["start-time"] = float(epoch - 600)
    if failure == "equal": window["expiration-time"] = window["start-time"]
    if failure == "reversed": window["expiration-time"] = epoch - 700
    if failure == "future": window["start-time"] = epoch + 1
    if failure == "expired": window["expiration-time"] = epoch - 1
    if failure == "timezone": window["timezone"] = "UTC"
    if failure == "malformed_string": window["start-time"] = "not-a-date"
    if failure == "absent_date": date = None
    if failure == "naive_date": date = _WINDOW_NOW.replace(tzinfo=None)
    if failure == "stale_date": date = _WINDOW_NOW - timedelta(seconds=301)
    if failure == "future_date": date = _WINDOW_NOW + timedelta(seconds=301)
    if failure == "pending_full_record": window["final-status"] = "pending"
    assert not secret_request_approval_revoke_launcher_window_available(window, server_time=date)
