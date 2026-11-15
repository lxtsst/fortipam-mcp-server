"""Pure minimized paired saved-selector observations; no connectivity authority."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from v4_planning.material_provider import _OpaqueC3Object

from .radius_server_contract import RadiusServerCreateBinding
from .radius_server_pair_contract import RadiusServerPairBinding, RadiusServerPairError
from .radius_server_owned_connect_contract import (
    CONNECT_PATH, RadiusOwnedConnectObservation, _spans, _equals, _TOP, _RESULT,
    matches_reject_only_connect_response, project_owned_connect_observation,
)
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = "fortipam-700-build29-radius-pair-owned-connect-observation-private-v1"
_ERROR = "The private paired RADIUS connect observation is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class RadiusPairOwnedConnectObservation(_OpaqueC3Object):
    ordinal: Literal["primary", "secondary"]
    http_status: int
    status_token: str | None
    result_status_only: bool
    negative_status: bool
    reject_only_shape: bool

    def __post_init__(self) -> None:
        if type(self.ordinal) is not str or self.ordinal not in {"primary", "secondary"}:
            raise RadiusServerPairError(_ERROR)
        RadiusOwnedConnectObservation(self.http_status, self.status_token, self.result_status_only, self.negative_status)
        if (type(self.reject_only_shape) is not bool or self.reject_only_shape
                and (self.http_status != 200 or self.status_token != "ok" or self.result_status_only)):
            raise RadiusServerPairError(_ERROR)

    def as_dict(self) -> dict[str, object]:
        return {"contract": CONTRACT, "ordinal": self.ordinal, "http_status": self.http_status,
            "status_token": self.status_token, "result_status_only": self.result_status_only,
            "negative_status": self.negative_status, "reject_only_shape": self.reject_only_shape,
            "observation_only": True, "connectivity_qualified": False}


def project_pair_owned_connect_observation(raw: bytearray, binding: RadiusServerPairBinding, *,
        ordinal: Literal["primary", "secondary"], expected_serial: str,
        http_status: int) -> RadiusPairOwnedConnectObservation:
    try:
        if type(raw) is not bytearray or not 0 < len(raw) <= 65536 or type(binding) is not RadiusServerPairBinding or type(ordinal) is not str or ordinal not in {"primary", "secondary"}:
            raise ValueError
        # Reuse only the same native envelope parser's saved selector. This
        # temporary primary type supplies no action, journal or pair ownership.
        selector = RadiusServerCreateBinding(binding.name, binding.server, binding.private_nonce)
        shape = matches_reject_only_connect_response(raw, selector, expected_serial=expected_serial, http_status=http_status)
        start = _skip_json_space(raw, 0)
        fields = _spans(raw, (start, _json_value_end(raw, start)), _TOP)
        if "results" in fields:
            result = _spans(raw, fields["results"], _RESULT)
            address = binding.server if ordinal == "primary" else binding.secondary_server
            if "server" in result and not _equals(raw, result, "server", address):
                raise ValueError
        observed = project_owned_connect_observation(raw, selector, expected_serial=expected_serial, http_status=http_status)
        return RadiusPairOwnedConnectObservation(ordinal, observed.http_status, observed.status_token,
            observed.result_status_only, observed.negative_status, shape)
    except Exception:
        raise RadiusServerPairError(_ERROR) from None
    finally:
        if isinstance(raw, bytearray):
            _zeroize_mutable(raw)
