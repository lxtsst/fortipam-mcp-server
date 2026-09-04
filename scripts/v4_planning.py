"""Stable repository entrypoint for the non-executable V4 M2/M3 model.

The implementation lives in :mod:`v4_planning`.  This module exists so the
administrative registry can carry a fixed repository evidence reference.  It
is not installed in the V3 wheel and is not an MCP or command-line entrypoint.
"""

from v4_planning import (  # noqa: F401
    ApprovalDenied,
    AuthenticatedApprover,
    AuthenticatedRequester,
    AuthoritativeProjection,
    DenyAllMaterialProvider,
    DenyAllProductAdapter,
    DesiredObject,
    InMemoryProtectedPlanningStore,
    M2PlanningEngine,
    M3ApprovalGate,
    M3PlanPolicy,
    MaterialReferenceMetadata,
    ObjectClass,
    PlanningDenied,
    ProtectedStoreError,
    ReferenceAuthorizer,
    SchemeDraft,
    SchemeId,
    VerifiedConfirmationInteraction,
    VerifiedReferenceDecision,
)

__all__ = [
    "ApprovalDenied",
    "AuthenticatedApprover",
    "AuthenticatedRequester",
    "AuthoritativeProjection",
    "DenyAllMaterialProvider",
    "DenyAllProductAdapter",
    "DesiredObject",
    "InMemoryProtectedPlanningStore",
    "M2PlanningEngine",
    "M3ApprovalGate",
    "M3PlanPolicy",
    "MaterialReferenceMetadata",
    "ObjectClass",
    "PlanningDenied",
    "ProtectedStoreError",
    "ReferenceAuthorizer",
    "SchemeDraft",
    "SchemeId",
    "VerifiedConfirmationInteraction",
    "VerifiedReferenceDecision",
]
