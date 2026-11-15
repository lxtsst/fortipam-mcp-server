"""Default-closed protected incident bootstrap, with no device I/O at startup.

Original five-key custody is verified by the existing signed runtime marker and
read-only quota bootstrap. New keys must be pre-provisioned at canonical paths.
No policy signer/admission, new root/nonce choice or MCP registration is exposed.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
import threading

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .instruction_quota_mcp_action import InstructionQuotaMcpAction
from .instruction_quota_reconciliation import InstructionQuotaRestoreReconciler
from .instruction_quota_recovery_contract import prepare_instruction_quota_baseline_recovery
from .instruction_quota_recovery_transport import FortiPamInstructionQuotaRecoveryTransport
from .instruction_quota_recovery_workflow import InstructionQuotaRecoveryWorkflow, _PREFIX
from .instruction_quota_runtime import (
    PREFIX as ORIGINAL_PREFIX, _build_instruction_quota_candidate_binding, _manifest,
)
from .ldap_server_runtime import _key, _path, _private_file, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable, load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_INSTRUCTION_QUOTA_RECOVERY_700_"
CONTRACT = "fortipam-700-build29-instruction-quota-incident-startup-v1"
_ERROR = "FortiPAM Instruction quota incident startup is unavailable."
_KEYS = {"native": ".native.key", "m4": ".m4.key", "policy": ".policy.key", "authority": ".authority.key"}
_CONSUMED = (".claim.json", ".ack.json", ".result.json", ".m4.attempt.json")


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, "false")
    if type(value) is not str or value not in {"true", "false"}:
        raise ValueError
    return value == "true"


def _original_binding(action: InstructionQuotaMcpAction, cohort: frozenset[str]) -> str:
    original = action._workflow
    config = original._transport._config
    config.__post_init__()
    return canonical_digest({"cohort": sorted(cohort), "native": original._transport._namespace,
        "binding": original._transport._binding.digest, "subject": original._authority._namespace,
        "origin": hashlib.sha256(config.base_url.encode()).hexdigest(),
        "token": hashlib.sha256(config.bearer_token.encode()).hexdigest(),
        "timeout": float(config.timeout_seconds).hex(),
        "ca": hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest() if config.ca_file else None})


def _identity(path: Path) -> tuple[int, int]:
    _private_file(path)
    info = path.lstat()
    return info.st_dev, info.st_ino


def _file_digest(path: Path) -> str:
    raw = _read(path, 16384)
    try:
        return hashlib.sha256(raw).hexdigest()
    finally:
        _zeroize_mutable(raw)


class InstructionQuotaRecoveryRuntime(_OpaqueC3Object):
    """Trusted local bootstrap; fresh workflow is created only on a preview."""

    def __init__(self, environment: Mapping[str, str], action: InstructionQuotaMcpAction,
            cohort: frozenset[str], keys: dict[str, bytes], store: PersistentM4ExecutionStateStore,
            *, execution_enabled: bool) -> None:
        # Construction remains an internal server operation, not an MCP argument surface.
        self._environment = dict(environment)
        self._original, self._cohort, self._keys, self._store = action, cohort, keys, store
        self._enabled = execution_enabled
        self._root = action._workflow._transport._directory
        self._pin = _original_binding(action, cohort)
        self._key_pins = {name: _identity(self._root / (_PREFIX + suffix)) for name, suffix in _KEYS.items()}
        self._store_pin = _identity(store._path)
        self._lock = threading.RLock()
        self._workflow: InstructionQuotaRecoveryWorkflow | None = None
        self._manifest_path = _path(environment[ORIGINAL_PREFIX + "STARTUP_MANIFEST_FILE"])
        self._manifest_pin = _file_digest(self._manifest_path)
        manifest = _manifest(self._manifest_path)
        self._old_key_paths = {name: _path(value) for name, value in manifest["paths"].items()
            if name.endswith("_hmac_key_file")}
        self._old_key_pins = {name: hashlib.sha256(_key(path)).hexdigest() for name, path in self._old_key_paths.items()}
        with action._workflow._transport.operation_lock(require_existing=True):
            self._original_lock_pin = action._workflow._transport._lock_id
            self._witness_pin = InstructionQuotaRestoreReconciler(action._workflow)._witness()
            self._marker_pin = action._workflow._transport._read("quota.runtime.json")
        self._guard()

    def _guard_locked(self) -> None:
        """Revalidate dispatch custody under the already-held original lock."""
        original = self._original._workflow
        original._transport._locked()
        if (original._transport._lock_id != self._original_lock_pin
                or _file_digest(self._manifest_path) != self._manifest_pin
                or {name: hashlib.sha256(_key(path)).hexdigest() for name, path in self._old_key_paths.items()} != self._old_key_pins
                or frozenset(self._old_key_pins.values()) != self._cohort
                or original._transport._read("quota.runtime.json") != self._marker_pin
                or _original_binding(self._original, self._cohort) != self._pin
                or load_secret_metadata_http_transport_config(self._environment) != original._transport._config
                or InstructionQuotaRestoreReconciler(original)._witness() != self._witness_pin
                or _identity(self._store._path) != self._store_pin):
            raise ValueError
        for name, suffix in _KEYS.items():
            path = self._root / (_PREFIX + suffix)
            if _identity(path) != self._key_pins[name] or _key(path) != self._keys[name]:
                raise ValueError
        self._store.verify_ready()

    def _guard(self) -> None:
        action, cohort = _build_instruction_quota_candidate_binding(self._environment, read_only_reconciliation=True)
        if (action is None or cohort != self._cohort or _original_binding(action, cohort) != self._pin
                or _identity(self._store._path) != self._store_pin):
            raise ValueError
        for name, suffix in _KEYS.items():
            path = self._root / (_PREFIX + suffix)
            if _identity(path) != self._key_pins[name] or _key(path) != self._keys[name]:
                raise ValueError
        self._store.verify_ready()
        original = action._workflow
        with original._transport.operation_lock(require_existing=True):
            if (original._transport._lock_id != self._original_lock_pin
                    or InstructionQuotaRestoreReconciler(original)._witness() != self._witness_pin):
                raise ValueError
        with self._original._workflow._transport.operation_lock(require_existing=True):
            self._guard_locked()

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._guard()
                identity = {"requester_digest": requester_digest, "transport_digest": transport_digest}
                self._original._workflow._identity(requester_digest, transport_digest)
                if self._workflow is not None:
                    return self._workflow.preview(**identity)
                original = self._original._workflow
                with original._transport.operation_lock(require_existing=True):
                    if self._store.claim_count or any(original._transport._exists(_PREFIX + suffix) for suffix in _CONSUMED):
                        raise ValueError
                candidate = prepare_instruction_quota_baseline_recovery(InstructionQuotaRestoreReconciler(original), **identity)
                writer = FortiPamInstructionQuotaRecoveryTransport(candidate,
                    state_key=self._keys["native"], execution_enabled=self._enabled)
                scope = original._authority._namespace
                self._workflow = InstructionQuotaRecoveryWorkflow(writer, execution_store=self._store,
                    policy_key=self._keys["policy"], authority_key=self._keys["authority"],
                    original_key_digests=self._cohort, environment_ref=scope["environment_ref"],
                    scope_ref=scope["scope_ref"], audience_ref=scope["audience_ref"], execution_enabled=self._enabled,
                    bootstrap_guard=self._guard_locked)
                return self._workflow._preview_prepared()
        except Exception:
            raise ValueError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                if not self._enabled or self._workflow is None:
                    raise ValueError
                self._guard()
                return self._workflow.authorize(preview_ref, requester_digest=requester_digest, transport_digest=transport_digest)
        except Exception:
            raise ValueError(_ERROR) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                if not self._enabled or self._workflow is None:
                    raise ValueError
                self._guard()
                return self._workflow.execute(authorization_ref, requester_digest=requester_digest, transport_digest=transport_digest)
        except Exception:
            raise ValueError(_ERROR) from None


def build_instruction_quota_recovery_candidate(environment: Mapping[str, str]) -> InstructionQuotaRecoveryRuntime | None:
    """No original initialization, policy provisioning or device read/write."""
    try:
        enabled, execution = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execution:
                raise ValueError
            return None
        if environment.get(ORIGINAL_PREFIX + "EXECUTION_ENABLED", "false") != "false":
            raise ValueError
        action, cohort = _build_instruction_quota_candidate_binding(environment, read_only_reconciliation=True)
        if action is None or len(cohort) != 5:
            raise ValueError
        original = action._workflow
        root = original._transport._directory
        with original._transport.operation_lock(require_existing=True):
            InstructionQuotaRestoreReconciler(original)._witness()
            keys = {name: _key(root / (_PREFIX + suffix)) for name, suffix in _KEYS.items()}
            if len(set(keys.values())) != 4 or any(hashlib.sha256(key).hexdigest() in cohort for key in keys.values()):
                raise ValueError
            database = root / (_PREFIX + ".m4.sqlite")
            if (not database.exists() and any(original._transport._exists(_PREFIX + suffix) for suffix in _CONSUMED)):
                raise ValueError
            store = PersistentM4ExecutionStateStore(database, root / (_PREFIX + ".m4.key"))
        return InstructionQuotaRecoveryRuntime(environment, action, cohort, keys, store, execution_enabled=execution)
    except Exception:
        raise ValueError(_ERROR) from None


__all__ = ["build_instruction_quota_recovery_candidate"]
