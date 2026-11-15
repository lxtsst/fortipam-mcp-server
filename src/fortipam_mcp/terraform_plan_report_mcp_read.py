"""One prebound synthetic Terraform report for its authenticated OAuth caller.

Only the protected startup descriptor selects files, issuer, profile and original
run. The no-input MCP read cannot create plans, sign receipts or invoke apply.
"""
from __future__ import annotations

from collections.abc import Mapping
import hmac
import json
import os
from pathlib import Path
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .folder_mcp_action import folder_action_principal_from_access_token
from .secret_bulk_import_file import _read_owned
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .terraform_plan_configuration import PinnedSignedTerraformConfigurationArtifact
from .terraform_plan_projection import _equals, _object
from .terraform_plan_receipt import TerraformPlanProducerPins, _hex_token, _integer
from .v4_plan_runtime import V4PlanningPrincipal

FEATURE_ENV = "FORTIPAM_MCP_V4_TERRAFORM_PLAN_REPORT_ENABLED"
BINDING_ENV = "FORTIPAM_MCP_V4_TERRAFORM_PLAN_REPORT_BINDING_FILE"
TOOL = "summarize_v4_synthetic_terraform_plan"
CONTRACT = "fortipam-terraform-plan-report/v1"
_BINDING_CONTRACT = b'"fortipam-terraform-plan-report-binding/v1"'
_ERROR = "The bound synthetic Terraform plan report is unavailable."
_PATHS = frozenset({"artifact_path", "receipt_path", "public_key_path"})
_DIGESTS = frozenset({"public_key_sha256", "run_nonce", "requester_digest", "transport_digest"})
_PINS = frozenset(TerraformPlanProducerPins.__dataclass_fields__)
_FIELDS = _PATHS | _DIGESTS | frozenset({"contract", "pins", "issued_at", "expires_at"})


class TerraformPlanReportError(ValueError):
    """Fixed denial without source, binding, identity or path disclosure."""


def load_terraform_plan_report_feature(environment: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise TerraformPlanReportError(_ERROR)


def terraform_plan_report_principal(access_token: Any, planning_settings: Any) -> V4PlanningPrincipal:
    try:
        principal = folder_action_principal_from_access_token(access_token, planning_settings)
        if type(principal) is not V4PlanningPrincipal:
            raise ValueError
        return principal
    except Exception:
        raise TerraformPlanReportError(_ERROR) from None


class ProtectedTerraformPlanReport(_OpaqueC3Object):
    """Deny another human/client before consuming the one signed artifact read."""

    def __init__(self, reader: PinnedSignedTerraformConfigurationArtifact) -> None:
        if type(reader) is not PinnedSignedTerraformConfigurationArtifact:
            raise TerraformPlanReportError(_ERROR)
        self._reader = reader
        self._requester = reader._bindings["requester_digest"]
        self._transport = reader._bindings["transport_digest"]

    def summarize(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if (type(principal) is not V4PlanningPrincipal
                    or not hmac.compare_digest(principal.requester.digest, self._requester)
                    or not hmac.compare_digest(principal.transport_namespace_digest, self._transport)):
                raise ValueError
            result = self._reader.read_once().summary()
            result.update(report_contract=CONTRACT, runtime_caller_authenticated=True,
                authenticated_requester_matches_receipt_binding=True,
                authenticated_transport_matches_receipt_binding=True,
                principal_values_returned=False)
            return result
        except Exception:
            raise TerraformPlanReportError(_ERROR) from None

    def close(self) -> None:
        self._reader.close()


def _path(content: bytearray, span: tuple[int, int]) -> Path:
    left, right = span
    if content[left] != 34 or right - left > 4096:
        raise ValueError
    # Decode only the three classified startup locators, never artifact scalars.
    with memoryview(content)[left:right] as value:
        text = json.loads(value.tobytes())
    if type(text) is not str or not text or "\x00" in text:
        raise ValueError
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    return path


def build_terraform_plan_report(environment: Mapping[str, str] | None = None) -> ProtectedTerraformPlanReport:
    """Read one owner-only typed descriptor; all selection stays server-side."""
    env = os.environ if environment is None else environment
    content = bytearray()
    try:
        if not load_terraform_plan_report_feature(env):
            raise ValueError
        path = Path(env[BINDING_ENV])
        content, _ = _read_owned(path)
        if not 0 < len(content) <= 16384:
            raise ValueError
        left = _skip_json_space(content, 0)
        right = _json_value_end(content, left)
        if _skip_json_space(content, right) != len(content):
            raise ValueError
        metadata._validate_json(content, left, right, depth=0, budget=[512])
        fields = _object(content, (left, right), _FIELDS)
        if set(fields) != _FIELDS or not _equals(content, fields["contract"], _BINDING_CONTRACT):
            raise ValueError
        pin_fields = _object(content, fields["pins"], _PINS)
        if set(pin_fields) != _PINS:
            raise ValueError
        pins = TerraformPlanProducerPins(**{key: _hex_token(content, value, 64) for key, value in pin_fields.items()})
        return ProtectedTerraformPlanReport(PinnedSignedTerraformConfigurationArtifact(
            pins=pins, artifact_path=_path(content, fields["artifact_path"]),
            receipt_path=_path(content, fields["receipt_path"]),
            public_key_path=_path(content, fields["public_key_path"]),
            public_key_sha256=_hex_token(content, fields["public_key_sha256"], 64),
            run_nonce=_hex_token(content, fields["run_nonce"], 64),
            requester_digest=_hex_token(content, fields["requester_digest"], 64),
            transport_digest=_hex_token(content, fields["transport_digest"], 64),
            issued_at=_integer(content, fields["issued_at"]), expires_at=_integer(content, fields["expires_at"])))
    except Exception:
        raise TerraformPlanReportError(_ERROR) from None
    finally:
        _zeroize_mutable(content)
