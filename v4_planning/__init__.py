"""Non-executable FortiPAM V4 M2/M3 planning contracts.

This repository-only package is intentionally excluded from the released V3
wheel and exposes no MCP, product, network, credential, or write interface.
"""

from .canonical import CanonicalValueError, canonical_digest, canonical_json
from .engine import (
    M2PlanningEngine,
    M2RegistryView,
    PlanningDenied,
    ReferenceAuthorizer,
    ReferenceIssuer,
)
from .models import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    ChangeKind,
    ConfirmationRecord,
    DesiredObject,
    FieldKind,
    FieldRule,
    FinalIntentSummary,
    MaterialReferenceMetadata,
    ObjectChange,
    ObjectClass,
    PlanLine,
    PlanState,
    PlanningContractError,
    PostWriteEvaluation,
    PostWriteStatus,
    PreparedPlan,
    PreWriteEvaluation,
    PreWriteStatus,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
    SummaryState,
    VerifiedConfirmationInteraction,
    VerifiedReferenceDecision,
)
from .approval import (
    ApprovalDenied,
    ApprovalReceipt,
    AuthenticatedApprover,
    M3ApprovalGate,
    PlanGateResult,
)
from .material_provider import (
    DenyAllMaterialProvider,
    MaterialAccessDenied,
    MaterialProvider,
)
from .policy import M3PlanPolicy, PlanPolicyDecision, PlanPolicyDenied
from .product_adapter import DenyAllProductAdapter, ProductAdapter, ProductDispatchDenied
from .store import InMemoryProtectedPlanningStore, ProtectedStoreError

__all__ = [
    "ApprovalDenied",
    "ApprovalReceipt",
    "AuthenticatedRequester",
    "AuthenticatedApprover",
    "AuthoritativeProjection",
    "CanonicalValueError",
    "ChangeKind",
    "ConfirmationRecord",
    "DesiredObject",
    "FieldKind",
    "FieldRule",
    "FinalIntentSummary",
    "DenyAllMaterialProvider",
    "DenyAllProductAdapter",
    "InMemoryProtectedPlanningStore",
    "M2PlanningEngine",
    "M2RegistryView",
    "M3ApprovalGate",
    "M3PlanPolicy",
    "MaterialAccessDenied",
    "MaterialProvider",
    "MaterialReferenceMetadata",
    "ObjectChange",
    "ObjectClass",
    "PlanLine",
    "PlanGateResult",
    "PlanPolicyDecision",
    "PlanPolicyDenied",
    "PlanState",
    "PlanningContractError",
    "PlanningDenied",
    "PostWriteEvaluation",
    "PostWriteStatus",
    "PreparedPlan",
    "ProductAdapter",
    "ProductDispatchDenied",
    "ProtectedStoreError",
    "PreWriteEvaluation",
    "PreWriteStatus",
    "ProjectionContract",
    "ReferenceIssuer",
    "ReferenceAuthorizer",
    "SchemeDraft",
    "SchemeId",
    "SummaryState",
    "VerifiedConfirmationInteraction",
    "VerifiedReferenceDecision",
    "canonical_digest",
    "canonical_json",
]
