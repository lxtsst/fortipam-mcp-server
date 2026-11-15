"""Bounded contract types for FortiPAM CSR generation."""

from __future__ import annotations

from dataclasses import dataclass


CSR_KEY_TYPE = "rsa"
CSR_KEY_SIZE = 2048
CSR_SCOPE = "global"


@dataclass(frozen=True, slots=True)
class CertificateCsrInspection:
    """Value-minimized CSR name availability evidence."""

    exists: bool
    name_available: bool


@dataclass(frozen=True, slots=True)
class CertificateCsrReadback:
    """Categorical readback that never returns CSR or private-key content."""

    entry_exists: bool
    name_matches: bool
    csr_present: bool
    private_key_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.entry_exists,
                self.name_matches,
                self.csr_present,
                self.private_key_present,
            )
        )


__all__ = [
    "CSR_KEY_SIZE",
    "CSR_KEY_TYPE",
    "CSR_SCOPE",
    "CertificateCsrInspection",
    "CertificateCsrReadback",
]
