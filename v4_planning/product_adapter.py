"""Deny-all product adapter for the V4 M3 plan-only candidate."""

from __future__ import annotations

from typing import NoReturn, Protocol

from .models import PreparedPlan


class ProductDispatchDenied(RuntimeError):
    """Raised because M3 has no FortiPAM write adapter."""


class ProductAdapter(Protocol):
    def dispatch(self, plan: PreparedPlan) -> NoReturn: ...


class DenyAllProductAdapter:
    """Reject every dispatch attempt without loading product configuration."""

    def dispatch(self, plan: PreparedPlan) -> NoReturn:
        del plan
        raise ProductDispatchDenied("FortiPAM product dispatch is unavailable in V4 M3.")


__all__ = ["DenyAllProductAdapter", "ProductAdapter", "ProductDispatchDenied"]
