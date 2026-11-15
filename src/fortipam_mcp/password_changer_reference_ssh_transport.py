"""Bounded read-only CLI check for FortiPAM 7.0 Password Changer references."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .password_changer_http_transport import SOURCE_NAME, _NAME
from .target_ssh_transport import (
    _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt,
)
from .template_ssh_transport import FortiPamTemplateSshTransport, TemplateSshTransportConfig


_UNAVAILABLE = "FortiPAM V4 Password Changer reference check is unavailable."
_CONTEXTS = ("template", "database", "target")
_TRUNCATION_MARKERS = (b"--more--", b"truncated", b"maximum output")
_SOURCE_RELATION = b'set password-changer-name "SSH Password (Unix)"'


class PasswordChangerReferenceSshTransportError(RuntimeError):
    """Stable non-disclosing reference-check failure."""


@dataclass(frozen=True, slots=True)
class PasswordChangerReferenceReadback:
    template_source_control_seen: bool
    template_reference_absent: bool
    secret_reference_absent: bool
    target_reference_absent: bool

    @property
    def verified_zero(self) -> bool:
        return all((
            self.template_source_control_seen,
            self.template_reference_absent,
            self.secret_reference_absent,
            self.target_reference_absent,
        ))


class FortiPamPasswordChangerReferenceSshTransport:
    """Scan only three fixed CLI contexts; never return their raw output."""

    def __init__(self, config: TemplateSshTransportConfig) -> None:
        self._transport = FortiPamTemplateSshTransport(config)

    def inspect(self, target_name: str) -> PasswordChangerReferenceReadback:
        if not isinstance(target_name, str) or _NAME.fullmatch(target_name) is None:
            raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
        try:
            return asyncio.run(self._inspect(target_name))
        except Exception:
            raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE) from None

    async def _inspect(self, target_name: str) -> PasswordChangerReferenceReadback:
        outputs: dict[str, bytes] = {}
        async with self._transport._connection() as connection:
            process, root_prompt, deadline = await self._transport._open_cli(connection)
            try:
                for context in _CONTEXTS:
                    table_prompt = await _send_and_read_dynamic_prompt(
                        process, f"config secret {context}", root_prompt, deadline,
                    )
                    output = await _send_and_read(
                        process, "show | grep changer -f", table_prompt, deadline,
                    )
                    returned_root = await _send_and_read_dynamic_prompt(
                        process, "end", root_prompt, deadline,
                    )
                    _require_root_prompt(root_prompt, returned_root)
                    outputs[context] = output
            finally:
                await _close_cli(process)
        return classify_password_changer_references(outputs, target_name)


def classify_password_changer_references(
    outputs: dict[str, bytes], target_name: str,
) -> PasswordChangerReferenceReadback:
    """Reject incomplete or ambiguous CLI evidence before claiming zero."""

    if not isinstance(target_name, str) or _NAME.fullmatch(target_name) is None:
        raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
    if set(outputs) != set(_CONTEXTS):
        raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
    normalized: dict[str, bytes] = {}
    for context, output in outputs.items():
        if not isinstance(output, bytes) or not output or len(output) > 64 * 1024:
            raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
        value = output.replace(b"\r", b"").lower()
        if any(marker in value for marker in _TRUNCATION_MARKERS):
            raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
        normalized[context] = value
    target = target_name.encode("ascii").lower()
    source_relation = _SOURCE_RELATION.lower()
    template = normalized["template"]
    if source_relation not in template or SOURCE_NAME.encode("ascii").lower() not in template:
        raise PasswordChangerReferenceSshTransportError(_UNAVAILABLE)
    return PasswordChangerReferenceReadback(
        template_source_control_seen=True,
        template_reference_absent=target not in template,
        secret_reference_absent=target not in normalized["database"],
        target_reference_absent=target not in normalized["target"],
    )


__all__ = [
    "FortiPamPasswordChangerReferenceSshTransport",
    "PasswordChangerReferenceReadback",
    "PasswordChangerReferenceSshTransportError",
    "classify_password_changer_references",
]
