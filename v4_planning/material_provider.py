"""Deny-all C3 material boundary for the V4 M3 plan-only candidate."""

from __future__ import annotations

from typing import NoReturn, Protocol


class MaterialAccessDenied(RuntimeError):
    """Raised because M3 has no C3 material authority."""


class MaterialProvider(Protocol):
    def acquire(self, material_ref: str, *, purpose: str) -> NoReturn: ...


class DenyAllMaterialProvider:
    """Make accidental C3 access structurally unavailable in M3."""

    def acquire(self, material_ref: str, *, purpose: str) -> NoReturn:
        del material_ref, purpose
        raise MaterialAccessDenied("C3 material access is unavailable in V4 M3.")


__all__ = ["DenyAllMaterialProvider", "MaterialAccessDenied", "MaterialProvider"]
