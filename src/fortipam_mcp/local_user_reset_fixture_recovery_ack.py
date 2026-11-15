"""Pure original DELETE acknowledgement candidate; never recovery authority."""
from __future__ import annotations

import hashlib
import hmac

from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from .local_user_reset_http_transport import _NAME
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable


def consume_reset_fixture_delete_ack(raw: bytearray, *, username: str, serial_digest: str,
        context_digest: str, http_status: int, content_type: str, witness_key: bytes) -> str:
    """One fixed private source-candidate grammar, bound to the actual response."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 16384
                or type(username) is not str or len(username) > 64 or _NAME.fullmatch(username) is None
                or type(http_status) is not int or http_status != 200
                or type(content_type) is not str or len(content_type) > 128
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or type(witness_key) is not bytes or not 32 <= len(witness_key) <= 128):
            raise ValueError
        require_digest(serial_digest, "reset_fixture_recovery_serial")
        require_digest(context_digest, "reset_fixture_recovery_context")
        left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        m._validate_json(raw, left, right, depth=0, budget=[50000])
        wanted: dict[str, str | int] = dict(version="v7.0.0", build=29, http_method="DELETE", http_status=200,
            status="success", path="system", name="admin", vdom="root", mkey=username)
        fields = m._object_spans(raw, left, right, frozenset(wanted) | {"serial", "error", "action", "results", "schema_errors"})
        if {"action", "results", "schema_errors"} & fields.keys():
            raise ValueError
        for key, value in wanted.items():
            actual = m._scalar(raw, fields[key])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = m._scalar(raw, fields["serial"])
        if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
            raise ValueError
        if "error" in fields:
            code = m._scalar(raw, fields["error"])
            if type(code) is not int or code != 0:
                raise ValueError
        digest = hmac.new(witness_key, b"local-reset-fixture-original-delete-ack/v1\x00" + context_digest.encode() + b"\x00", hashlib.sha256)
        digest.update(raw)
        return digest.hexdigest()
    except Exception:
        raise ValueError("The private original reset-fixture DELETE acknowledgement is unavailable.") from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
