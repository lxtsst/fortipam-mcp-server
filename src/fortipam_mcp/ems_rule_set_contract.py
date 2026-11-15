"""Fixed private EMS7.4.8 rule-set requests from the owner-supplied FNDN export.

The export has no response contracts. These codecs provide neither transport
nor original ownership, Tag linkage, native effects or cleanup authority. The
old Tag POST recovery and its consumed evidence remain separate and unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from .ems_tag_contract import DisabledLinuxProcessTag,_canonical

CONTRACT='ems-7.4.8-rule-set-request-description-local/v1'
REQUEST_SOURCE_SHA256='23be1f27c3599bcc85455338f073f0055def92ad8706208caa6d033f593ab584'
INDEX_PATH='/api/v1/tag_rules/zero_trust/index?offset=0&count=33'
CREATE_PATH='/api/v1/tag_rules/zero_trust/create'
DELETE_PATH='/api/v1/tag_rules/zero_trust/delete'
MAX_RULE_SETS=32
_ERROR='The private EMS rule-set request is unavailable.'


def _identifier(value: int) -> int:
    # A conservative local integer profile, not an upstream maximum assertion.
    if type(value) is not int or not 1<=value<=2147483647: raise ValueError(_ERROR)
    return value


def rule_set_detail_path(identifier: int) -> str:
    return '/api/v1/tag_rules/zero_trust/'+str(_identifier(identifier))+'/get'


@dataclass(frozen=True,slots=True,repr=False)
class DisabledProcessRuleSetRequest(_OpaqueC3Object):
    """One disabled process profile; no inference of native numeric rule enums.

    PROCESS/Linux values reuse the qualified Tag profile. The FNDN description
    qualifies their integer types here, not this separate operation's behavior.
    Creating a rule set may change the associated Tag and its evaluation.
    """
    _tag_id: int
    _draft: DisabledLinuxProcessTag

    def __post_init__(self) -> None:
        try:
            _identifier(self._tag_id)
            if type(self._draft) is not DisabledLinuxProcessTag: raise ValueError
            self._draft.__post_init__()
        except Exception: raise ValueError(_ERROR) from None

    @property
    def _body(self) -> dict[str,object]:
        self.__post_init__(); body=self._draft._body
        return dict(status=False,tag=self._tag_id,comments=body['comments'],rules=body['rules'],use_custom_logic=False)

    @property
    def parameters_digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,source=REQUEST_SOURCE_SHA256,method='POST',path=CREATE_PATH,body=self._body))

    def _compile(self) -> bytearray:
        return bytearray(_canonical(self._body))


@dataclass(frozen=True,slots=True,repr=False)
class SingleRuleSetDeleteRequest(_OpaqueC3Object):
    """Serialize one ID only; an integer or matching view is never custody."""
    _rule_set_id: int

    def __post_init__(self) -> None:
        _identifier(self._rule_set_id)

    @property
    def _body(self) -> dict[str,object]:
        self.__post_init__(); return dict(ids=[self._rule_set_id])

    @property
    def parameters_digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,source=REQUEST_SOURCE_SHA256,method='POST',path=DELETE_PATH,body=self._body))

    def _compile(self) -> bytearray:
        return bytearray(_canonical(self._body))


def rule_set_request_boundary() -> dict[str,object]:
    """Value-free source facts; never classify an actual request as authorized."""
    return dict(contract=CONTRACT,source_version='7.4.8',source_kind='owner_supplied_fndn_request_description',
        fixed_local_catalog_limit=MAX_RULE_SETS,local_query_fetches_one_overflow_row=True,
        catalog_filter_completeness_verified=False,response_contract_verified=False,
        native_rule_set_behavior_verified=False,original_tag_and_rule_set_custody_required=True,
        tag_association_or_rule_evaluation_may_change=True,disabled_does_not_prove_no_access_effect=True,
        create_requires_empty_original_owned_tag_linkage=True,delete_requires_original_birth_and_fresh_no_usage=True,
        tag_and_rule_set_deletion_are_separate_operations=True,implicit_cascade_cleanup_verified=False,
        native_automatic_recovery_verified=False,old_tag_post_recovery_reinterpreted=False,
        source_or_request_grants_authority=False,execution_authorized=False,device_contacted=False)
