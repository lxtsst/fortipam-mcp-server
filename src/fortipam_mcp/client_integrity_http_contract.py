"""Non-dispatchable build-29 native external package contracts.

Names and configuration remain inside the protected adapter. This module
neither downloads software nor qualifies signature enforcement or deletion.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any


CONTRACT = "fortipam_v4_client_integrity_native_form_700_v3"
HASH_CONTRACT = "fortipam_v4_client_integrity_native_hash_form_700_v1"
EXTERNAL_URL = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"
CERTIFICATE_NAME = "Fortinet_CA_SSL"
_NAME = re.compile(r"mcp-v4-client-integrity-rest-[0-9]{8}-r[1-9][0-9]{0,3}\Z")
_HASH_NAME = re.compile(r"mcp-v4-client-integrity-hash-[0-9]{8}-r[1-9][0-9]{0,3}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_UNAVAILABLE = "The fixed native Client Software contract is unavailable."


class ClientIntegrityHttpContractError(ValueError):
    """Reject an unqualified body or read without disclosing private values."""


@dataclass(frozen=True, slots=True, repr=False)
class NativeClientIntegrityReadback:
    """Configuration evidence only; no reference completeness or cleanup grant."""

    configuration_digest: str
    reported_reference_count_is_zero: bool


def _envelope(payload: object) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError
    fixed = {
        "version": "v7.0.0", "build": 29, "http_method": "GET",
        "http_status": 200, "path": "secret", "name": "client-software",
    }
    if (any(type(payload.get(key)) is not type(value) or payload[key] != value
            for key, value in fixed.items())
            or payload.get("status") not in {"success", "OK"}
            or payload.get("vdom") != "root"):
        raise ValueError
    return payload


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ValueError
    return value


def _hash_name(value: str) -> str:
    if not isinstance(value, str) or _HASH_NAME.fullmatch(value) is None:
        raise ValueError
    return value


def _hash_package(executable_sha256: str) -> dict[str, str]:
    if (not isinstance(executable_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", executable_sha256) is None):
        raise ValueError
    return {
        **_package(), "integrity-check": "exe-hash", "hash-algo": "SHA-256",
        "hash": executable_sha256, "ca": "",
    }


def _package() -> dict[str, str]:
    # Explicit native form values; backend defaults are not copied.
    return {
        "name": "x64", "app-type": "native", "os": "win", "browser": "chrome",
        "integrity-check": "cert", "hash-algo": "MD5", "hash": "",
        "ca": CERTIFICATE_NAME, "download-option": "external",
        "package-name": "", "external-url": EXTERNAL_URL,
    }


def _native_metadata(object_type: int) -> dict[str, object]:
    if type(object_type) is not int or not 0 <= object_type <= 999_999_999:
        raise ValueError
    return {"q_global_entry": False, "q_path": "secret", "q_name": "client-software",
            "q_type": object_type, "q_mkey_type": "string", "q_no_edit": False,
            "q_no_rename": False}


def compile_native_client_integrity_create_body(
    default_payload: object, *, software_name: str,
) -> dict[str, object]:
    """Compile one fixed native body, not an authorization or absence proof.

    A transport must separately verify the certificate, target absence,
    preserved collection and durable one-shot authorization before POST.
    """
    try:
        payload = _envelope(default_payload)
        name = _name(software_name)
        row = payload.get("results")
        if (not isinstance(row, Mapping) or set(row) != {"name", "pkg"}
                or row["name"] != "" or type(row["pkg"]) is not list or row["pkg"]):
            raise ValueError
        return {"name": name, "pkg": [_package()], "$originalName": ""}
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None


def compile_native_client_integrity_hash_create_body(
    default_payload: object, *, software_name: str, executable_sha256: str,
) -> dict[str, object]:
    """Compile the qualified native hash form in a separate fixture namespace.

    The hash must come from independently verified executable bytes in the
    private adapter, never an MCP argument or the mutable latest URL alone.
    This compiler grants no write, compatibility, readback or recovery authority;
    the accepted certificate profile and its consumed records remain distinct.
    """
    try:
        payload = _envelope(default_payload)
        _hash_name(software_name)
        package = _hash_package(executable_sha256)
        row = payload.get("results")
        if (not isinstance(row, Mapping) or set(row) != {"name", "pkg"}
                or row["name"] != "" or type(row["pkg"]) is not list or row["pkg"]):
            raise ValueError
        return {"name": software_name, "pkg": [package], "$originalName": ""}
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None


def project_native_client_integrity_detail(
    payload: object, *, software_name: str,
) -> NativeClientIntegrityReadback:
    """Keep the accepted certificate profile's exact complete projection."""
    try:
        return _project_native_client_integrity_detail(
            payload, software_name=_name(software_name), expected_package=_package(),
        )
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None


def project_native_client_integrity_hash_detail(
    payload: object, *, software_name: str, executable_sha256: str,
) -> NativeClientIntegrityReadback:
    """Strict candidate hash readback; live canonicalization remains unqualified.

    The existing native identity canonicalization is an explicit candidate
    expectation. A different real response must reconcile, never be normalized
    or treated as enforcement, ownership or deletion authority.
    """
    try:
        return _project_native_client_integrity_detail(
            payload, software_name=_hash_name(software_name),
            expected_package=_hash_package(executable_sha256),
        )
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None


def _project_native_client_integrity_detail(
    payload: object, *, software_name: str, expected_package: dict[str, str],
) -> NativeClientIntegrityReadback:
    """Seal one complete expected no-upload record with value-free evidence.

    Missing q_ref remains unknown. Reported zero never authorizes recovery by
    itself; independent native reference evidence and creation ownership are
    required. Uploaded content must be excluded before general response decode
    by the eventual transport; this projection admits only an empty token.
    """
    try:
        envelope = _envelope(payload)
        name = software_name
        row = envelope.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping):
            raise ValueError
        metadata = _native_metadata(row["q_type"])
        if (not isinstance(row, Mapping) or not {"name", "pkg", "q_origin_key", *metadata} <= set(row)
                or not set(row) <= {"name", "pkg", "q_origin_key", "q_ref", "q_static", *metadata}
                or row["name"] != name or row["q_origin_key"] != name):
            raise ValueError
        if any(type(row[key]) is not type(value) or row[key] != value for key, value in metadata.items()):
            raise ValueError
        if "q_static" in row and row["q_static"] is not False:
            raise ValueError
        if "q_ref" in row and (type(row["q_ref"]) is not int or row["q_ref"] < 0):
            raise ValueError
        packages = row["pkg"]
        if type(packages) is not list or len(packages) != 1 or not isinstance(packages[0], Mapping):
            raise ValueError
        package = packages[0]
        # Build 29 canonicalizes these inactive/native identity fields.
        # The submitted form still contains Chrome and no client-name.
        expected: dict[str, object] = {
            **expected_package, "browser": "edge", "q_origin_key": "x64", "client-name": name,
            "description": "", "file-size": 0, "package-content": "", "state": "absent",
        }
        if (set(package) != {*expected, "uuid"}
                or any(type(package.get(key)) is not type(value) or package[key] != value
                       for key, value in expected.items())
                or not isinstance(package["uuid"], str) or _UUID.fullmatch(package["uuid"]) is None):
            raise ValueError
        serialized = json.dumps(dict(row), sort_keys=True, separators=(",", ":")).encode()
        return NativeClientIntegrityReadback(
            hashlib.sha256(serialized).hexdigest(),
            "q_ref" in row and row["q_ref"] == 0,
        )
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None


def validate_native_client_integrity_recovery_state(
    detail_payload: object, usage_payload: bytearray, *, software_name: str,
    expected_configuration_digest: str,
) -> None:
    """Preserve the certificate profile's state and fresh usage preconditions."""
    current = project_native_client_integrity_detail(detail_payload, software_name=software_name)
    _validate_native_client_integrity_recovery_state(
        detail_payload, usage_payload, software_name=_name(software_name),
        expected_configuration_digest=expected_configuration_digest, current=current,
    )


def validate_native_client_integrity_hash_recovery_state(
    detail_payload: object, usage_payload: bytearray, *, software_name: str,
    executable_sha256: str, expected_configuration_digest: str,
) -> None:
    """Hash state/usage guard only; no creation or recovery authority is inferred."""
    current = project_native_client_integrity_hash_detail(
        detail_payload, software_name=software_name, executable_sha256=executable_sha256,
    )
    _validate_native_client_integrity_recovery_state(
        detail_payload, usage_payload, software_name=_hash_name(software_name),
        expected_configuration_digest=expected_configuration_digest, current=current,
    )


def _validate_native_client_integrity_recovery_state(
    detail_payload: object, usage_payload: bytearray, *, software_name: str,
    expected_configuration_digest: str, current: NativeClientIntegrityReadback,
) -> None:
    """Require complete owned-state equality and fresh reported empty usage.

    This is a state precondition, not creation ownership or delete authority.
    The eventual transport must bind the native object type, exact usage query,
    verified creation receipt, recovery intent and separate durable claim.
    """
    try:
        from .local_user_reset_metadata_reader import _monitor_results, _array_count, _validate_value
        from .local_user_reset_projection import _object_spans

        if (not isinstance(expected_configuration_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", expected_configuration_digest) is None
                or type(usage_payload) is not bytearray):
            raise ValueError
        if not hmac.compare_digest(current.configuration_digest, expected_configuration_digest):
            raise ValueError
        envelope = _envelope(detail_payload)
        row = envelope["results"]
        if isinstance(row, list):
            row = row[0]
        if "q_ref" in row and row["q_ref"] != 0:
            raise ValueError
        start, end = _monitor_results(
            usage_payload, expected_route="system/object/usage", expected_mkey=software_name,
        )
        members = _object_spans(usage_payload, start, end)
        if "currently_using" not in members:
            raise ValueError
        for left, right in members.values():
            _validate_value(usage_payload, left, right, depth=0)
        if _array_count(usage_payload, *members["currently_using"], depth=0, objects_only=True) != 0:
            raise ValueError
    except Exception:
        raise ClientIntegrityHttpContractError(_UNAVAILABLE) from None
