"""Private configuration-tree extension of the fixed Terraform plan projection.

This examines every supported module/resource/provisioner node without decoding
locators, expression values or commands. It produces structural risk metadata,
not permission, an effect assessment, source provenance or apply authority.
The existing action-only projection and signed-receipt contract stay unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import hmac

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_bulk_import_file import _read_owned
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .terraform_plan_projection import (
    CONTRACT as BASE_CONTRACT, Span, TerraformPlanProjection, _DATA, _FOLDER, _SECRET, _TOP, _PROVIDER_FIELDS,
    _equals, _object, project_private_terraform_plan,
)
from .terraform_plan_receipt import (
    PinnedSignedTerraformPlanArtifact, SignedTerraformPlanProjection, TerraformPlanReceiptError,
    _ERROR as _RECEIPT_ERROR,
)

CONTRACT = "fortipam-terraform-plan-configuration-metadata-private-v1"
_ERROR = "The private Terraform configuration projection is unavailable."
_MODULE = frozenset({"outputs", "resources", "module_calls", "variables", "actions"})
_CALL = frozenset({"source", "expressions", "count_expression", "for_each_expression", "module",
    "version_constraint", "depends_on"})
_RESOURCE = frozenset({"address", "mode", "type", "name", "provider_config_key", "provisioners",
    "expressions", "schema_version", "count_expression", "for_each_expression", "depends_on"})
_PROVISIONER = frozenset({"type", "expressions"})
_PROVISIONER_TYPES = (b'"local-exec"', b'"remote-exec"', b'"file"')
_PROVISIONER_NAMES = ("local_exec", "remote_exec", "file")
_EXPRESSION_FIELDS = (
    frozenset({"parent", "name", "path"}),
    frozenset({"path", "name", "template", "fields"}),
    frozenset({"path", "name", "field", "value"}),
)


class ConfigurationStage(StrEnum):
    INPUT = "private_input"
    BASE = "base_projection"
    PROVIDERS = "provider_keys"
    MODULE = "module_structure"
    RESOURCE = "resource_structure"
    BINDING = "provider_binding"
    PROVISIONER = "provisioner_structure"
    RESULT = "result_projection"


class TerraformConfigurationProjectionError(ValueError):
    def __init__(self, stage: ConfigurationStage) -> None:
        super().__init__(_ERROR)
        self.stage = stage if type(stage) is ConfigurationStage else ConfigurationStage.INPUT


def _string_fingerprint(content: bytearray, span: Span) -> str:
    """Compare opaque JSON strings semantically, without creating decoded text.

    Escaped aliases and surrogate pairs must match ordinary UTF8 spellings;
    semantic duplicates cannot choose a different provider by wire encoding.
    """
    left, right = span
    if content[left] != 34 or content[right - 1] != 34:
        raise ValueError
    digest = hashlib.sha256()
    cursor = segment = left + 1
    escapes = {34: 34, 92: 92, 47: 47, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9}
    def codepoint(at: int) -> int:
        value = 0
        for index in range(at, at + 4):
            byte = content[index]
            value = value * 16 + (byte - 48 if byte <= 57 else byte - 87 if byte >= 97 else byte - 55)
        return value
    with memoryview(content) as source:
        while cursor < right - 1:
            if content[cursor] != 92:
                cursor += 1
                continue
            digest.update(source[segment:cursor]); cursor += 1
            escape = content[cursor]
            if escape != 117:
                digest.update(bytes((escapes[escape],))); cursor += 1
            else:
                value = codepoint(cursor + 1); cursor += 5
                if 0xD800 <= value <= 0xDBFF:
                    if cursor + 6 > right - 1 or content[cursor] != 92 or content[cursor + 1] != 117:
                        raise ValueError
                    low = codepoint(cursor + 2)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise ValueError
                    value = 0x10000 + ((value - 0xD800) << 10) + low - 0xDC00
                    cursor += 6
                elif 0xDC00 <= value <= 0xDFFF:
                    raise ValueError
                if value < 0x80: encoded = bytes((value,))
                elif value < 0x800: encoded = bytes((0xC0 | value >> 6, 0x80 | value & 63))
                elif value < 0x10000: encoded = bytes((0xE0 | value >> 12, 0x80 | value >> 6 & 63, 0x80 | value & 63))
                else: encoded = bytes((0xF0 | value >> 18, 0x80 | value >> 12 & 63, 0x80 | value >> 6 & 63, 0x80 | value & 63))
                digest.update(encoded)
            segment = cursor
        digest.update(source[segment:right - 1])
    return digest.hexdigest()


def _items(content: bytearray, span: Span) -> list[tuple[str, Span]]:
    left, right = span
    if content[left] != 123 or content[right - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    result: list[tuple[str, Span]] = []
    seen = set()
    while cursor < right - 1:
        if len(result) >= 128:
            raise ValueError
        end = _json_value_end(content, cursor)
        key = _string_fingerprint(content, (cursor, end))
        if key in seen:
            raise ValueError
        seen.add(key)
        separator = _skip_json_space(content, end)
        if content[separator] != 58:
            raise ValueError
        start = _skip_json_space(content, separator + 1)
        end = _json_value_end(content, start)
        result.append((key, (start, end)))
        cursor = _skip_json_space(content, end)
        if cursor < right - 1:
            cursor = _skip_json_space(content, cursor + 1)
    return result


def _references(content: bytearray, span: Span) -> None:
    for reference in metadata._array(content, span, 4096):
        if content[reference[0]] != 34:
            raise ValueError


def _expression(content: bytearray, span: Span) -> None:
    fields = _object(content, span, frozenset({"constant_value", "references"}))
    if "references" in fields:
        _references(content, fields["references"])


def _optional_structure(content: bytearray, fields: dict[str, Span]) -> None:
    for key in ("source", "version_constraint", "description"):
        if key in fields and content[fields[key][0]] != 34:
            raise ValueError
    if "sensitive" in fields and not any(_equals(content, fields["sensitive"], value) for value in (b"true", b"false")):
        raise ValueError
    if "depends_on" in fields:
        _references(content, fields["depends_on"])
    for key in ("count_expression", "for_each_expression"):
        if key in fields:
            _expression(content, fields[key])


class _Walk:
    def __init__(self) -> None:
        self.stage = ConfigurationStage.INPUT
        self.modules = self.resources = self.material = self.outputs = 0
        self.provisioners = [0, 0, 0]

    def module(self, content: bytearray, span: Span, providers: set[str], *, depth: int = 0) -> None:
        self.stage = ConfigurationStage.MODULE
        self.modules += 1
        if self.modules > 128 or depth > 8:
            raise ValueError
        fields = _object(content, span, _MODULE)
        if "actions" in fields and metadata._array(content, fields["actions"], 0):
            raise ValueError  # The pinned provider exposes no action schema.
        if "outputs" in fields:
            for _, output in _items(content, fields["outputs"]):
                selected = _object(content, output, frozenset({"sensitive", "expression", "depends_on", "description"}))
                if "expression" not in selected:
                    raise ValueError
                _optional_structure(content, selected)
                _expression(content, selected["expression"])
                self.outputs += 1
                if self.outputs > 4096:
                    raise ValueError
        if "variables" in fields:
            for _, variable in _items(content, fields["variables"]):
                selected = _object(content, variable, frozenset({"default", "description", "sensitive"}))
                _optional_structure(content, selected)
        addresses: set[str] = set()
        if "resources" in fields:
            for item in metadata._array(content, fields["resources"], 4096):
                self.resource(content, item, providers, addresses)
        self.stage = ConfigurationStage.MODULE
        if "module_calls" in fields:
            for _, call in _items(content, fields["module_calls"]):
                selected = _object(content, call, _CALL)
                _optional_structure(content, selected)
                if "module" not in selected:
                    raise ValueError
                if "expressions" in selected:
                    for _, expression in _items(content, selected["expressions"]):
                        _expression(content, expression)
                self.module(content, selected["module"], providers, depth=depth + 1)

    def resource(self, content: bytearray, span: Span, providers: set[str], addresses: set[str]) -> None:
        self.stage = ConfigurationStage.RESOURCE
        fields = _object(content, span, _RESOURCE)
        _optional_structure(content, fields)
        if not {"address", "mode", "type", "name", "provider_config_key", "schema_version"} <= fields.keys():
            raise ValueError
        address = _string_fingerprint(content, fields["address"])
        if address in addresses:
            raise ValueError
        addresses.add(address); _string_fingerprint(content, fields["name"])
        managed = _equals(content, fields["mode"], b'"managed"')
        if managed and _equals(content, fields["type"], _FOLDER): kind = 0
        elif managed and _equals(content, fields["type"], _SECRET): kind = 1
        elif _equals(content, fields["mode"], b'"data"') and _equals(content, fields["type"], _DATA): kind = 2
        else: raise ValueError
        if not _equals(content, fields["schema_version"], b"0"):
            raise ValueError
        if "expressions" in fields:
            expressions = _object(content, fields["expressions"], _EXPRESSION_FIELDS[kind])
            for name, expression in expressions.items():
                # Secret fields is a classified material block, not scalar
                # expression metadata. Its private values remain untouched.
                if kind != 1 or name != "fields":
                    _expression(content, expression)
        self.stage = ConfigurationStage.BINDING
        if _string_fingerprint(content, fields["provider_config_key"]) not in providers:
            raise ValueError
        self.resources += 1; self.material += int(kind != 0)
        self.stage = ConfigurationStage.RESOURCE
        if self.resources > 4096:
            raise ValueError
        self.stage = ConfigurationStage.PROVISIONER
        if "provisioners" in fields:
            if not managed:
                raise ValueError
            for item in metadata._array(content, fields["provisioners"], 64):
                selected = _object(content, item, _PROVISIONER)
                matches = [index for index, literal in enumerate(_PROVISIONER_TYPES)
                    if _equals(content, selected["type"], literal)]
                if len(matches) != 1 or "expressions" not in selected or content[selected["expressions"][0]] != 123:
                    raise ValueError
                for _, expression in _items(content, selected["expressions"]):
                    _expression(content, expression)
                self.provisioners[matches[0]] += 1
                if sum(self.provisioners) > 4096:
                    raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class TerraformConfigurationProjection(_OpaqueC3Object):
    base: TerraformPlanProjection
    module_entries: int
    resource_entries: int
    material_resource_entries: int
    output_entries: int
    provisioner_counts: tuple[int, int, int]

    def summary(self) -> dict[str, object]:
        result = self.base.summary()
        findings = {"provider_effects_and_permissions_unverified"}
        if self.material_resource_entries or self.base.material_resource_entries:
            findings.add("credential_plan_or_state_exposure_possible")
        if any(self.provisioner_counts): findings.add("provisioner_effects_require_review")
        if self.base.folder_update_or_replace_entries: findings.add("folder_acl_preservation_unqualified")
        if self.base.tls_unproven_provider_entries: findings.add("tls_verification_unproven")
        if self.base.reported_errored: findings.add("producer_reported_errored")
        if self.base.reported_complete is not True: findings.add("plan_completion_unproven")
        if self.base.deferred_changes_present: findings.add("deferred_changes_present")
        if any(self.base.action_counts[index] for index in (3, 5, 6, 7, 8, 9)):
            findings.add("destructive_or_state_forget_effect")
        if self.output_entries: findings.add("output_values_excluded_from_review")
        result.update(contract=CONTRACT, base_contract=BASE_CONTRACT, scope="action_and_configuration_metadata",
            configuration_tree_structure_checked=True, configuration_provider_references_matched=True,
            configuration_module_entries=self.module_entries, configuration_resource_entries=self.resource_entries,
            configuration_material_resource_entries=self.material_resource_entries, configuration_output_entries=self.output_entries,
            provisioner_entry_counts=dict(zip(_PROVISIONER_NAMES, self.provisioner_counts, strict=True)),
            provisioner_effects_require_review=any(self.provisioner_counts), expression_values_reviewed=False,
            findings=sorted(findings))
        return result


def project_private_terraform_configuration(content: bytearray) -> TerraformConfigurationProjection:
    """Own both mutable buffers; old projection semantics are not extended."""
    duplicate = bytearray(); walk = _Walk()
    try:
        if type(content) is not bytearray or not 0 < len(content) <= 2 * 1024 * 1024:
            raise ValueError
        duplicate = bytearray(content)
        walk.stage = ConfigurationStage.BASE
        base = project_private_terraform_plan(duplicate)
        left = _skip_json_space(content, 0); right = _json_value_end(content, left)
        fields = _object(content, (left, right), _TOP)
        configuration = _object(content, fields["configuration"], frozenset({"provider_config", "root_module"}))
        walk.stage = ConfigurationStage.PROVIDERS
        entries = _items(content, configuration["provider_config"])
        providers = {key for key, _ in entries}
        for _, entry in entries:
            provider = _object(content, entry, _PROVIDER_FIELDS)
            for key in ("name", "full_name", "alias", "module_address", "version_constraint"):
                if key in provider and content[provider[key][0]] != 34:
                    raise ValueError
            for _, expression in _items(content, provider["expressions"]):
                _expression(content, expression)
        walk.module(content, configuration["root_module"], providers)
        walk.stage = ConfigurationStage.RESULT
        return TerraformConfigurationProjection(base, walk.modules, walk.resources, walk.material, walk.outputs,
            (walk.provisioners[0], walk.provisioners[1], walk.provisioners[2]))
    except Exception:
        raise TerraformConfigurationProjectionError(walk.stage) from None
    finally:
        if type(content) is bytearray:
            _zeroize_mutable(content)
        _zeroize_mutable(duplicate)


@dataclass(frozen=True, slots=True, repr=False)
class SignedTerraformConfigurationProjection(SignedTerraformPlanProjection):
    configuration: TerraformConfigurationProjection

    def __post_init__(self) -> None:
        if type(self.configuration) is not TerraformConfigurationProjection or self.projection is not self.configuration.base:
            raise TerraformPlanReceiptError(_RECEIPT_ERROR)

    def summary(self) -> dict[str, object]:
        result = SignedTerraformPlanProjection.summary(self)
        result.update(self.configuration.summary())
        return result


class PinnedSignedTerraformConfigurationArtifact(PinnedSignedTerraformPlanArtifact):
    """Separate fixed structural reader; original action-only entry is unchanged.

    It uses the same read-only input attestation, not a new signing authority.
    Signature/time/subject checks still precede the only artifact acquisition.
    No caller callback, raw selector or projection-mode argument is accepted.
    """

    def read_once(self) -> SignedTerraformConfigurationProjection:
        receipt = public = artifact = bytearray()
        try:
            with self._lock:
                if self._attempted or self._closed:
                    raise ValueError
                self._attempted = True
            self._configuration_failure_stage: ConfigurationStage | None = None
            self._check()
            public = self._public.load()
            receipt, _ = _read_owned(self._receipt)
            digest, size = self._authenticate(receipt, public)
            self._check()
            artifact, _ = _read_owned(self._artifact)
            if len(artifact) != size or not hmac.compare_digest(hashlib.sha256(artifact).hexdigest(), digest):
                raise ValueError
            configuration = project_private_terraform_configuration(artifact)
            fresh_public = self._public.load()
            _zeroize_mutable(fresh_public)
            self._check()
            return SignedTerraformConfigurationProjection(configuration.base, configuration)
        except TerraformConfigurationProjectionError as error:
            self._configuration_failure_stage = error.stage
            raise TerraformPlanReceiptError(_RECEIPT_ERROR) from None
        except Exception:
            raise TerraformPlanReceiptError(_RECEIPT_ERROR) from None
        finally:
            for raw in (receipt, public, artifact):
                _zeroize_mutable(raw)
