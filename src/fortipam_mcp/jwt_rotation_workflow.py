"""One bounded JWT identity/overlap/cutover/restore outcome with six child M4s."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import math
import os
from pathlib import Path
import secrets
import time
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .jwt_manual_key_contract import _digest
from .jwt_rotation_authentication import JwtRotationAuthenticationProbe, JwtRotationAuthenticationError
from .jwt_rotation_owner_source import JwtRotationOwnerSource, PHASES
from .jwt_rotation_phase import JwtRotationPhase
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_operation_records import _TargetOperationRecords

CONTRACT = "fortipam-build29-jwt-rotation-workflow-v5"
DIAGNOSTIC_CONTRACT = "fortipam-build29-manual-jwt-update-discriminator-v3"
_ERROR = "The fixed JWT rotation workflow is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class JwtRotationPhaseSpec(_OpaqueC3Object):
    store: PersistentM4ExecutionStateStore
    directory: Path
    authority_key_file: Path
    scope_ref: str


class JwtRotationWorkflow(_TargetOperationRecords):
    def __init__(self, source: JwtRotationOwnerSource, probe_factory: Callable[[],JwtRotationAuthenticationProbe],
            phases: dict[str,JwtRotationPhaseSpec], *, directory: Path, authority_key_file: Path,
            environment_ref: str, audience_ref: str, execution_enabled: bool = False,
            activation_diagnostic: bool = False, sampling_clock: Callable[[],float] | None = None,
            sampling_wait: Callable[[float],None] | None = None) -> None:
        try:
            if (type(source) is not JwtRotationOwnerSource or not callable(probe_factory)
                    or type(phases) is not dict or set(phases) != set(PHASES)
                    or type(execution_enabled) is not bool or type(activation_diagnostic) is not bool
                    or sampling_clock is not None and not callable(sampling_clock)
                    or sampling_wait is not None and not callable(sampling_wait)):
                raise ValueError
            require_ref(environment_ref,"environment_ref"); require_ref(audience_ref,"audience_ref")
            _private_directory(directory)
            self.source,self.phases = source,dict(phases)
            self.probe: JwtRotationAuthenticationProbe | None = None
            self._probe_factory,self._probe_factory_pin = probe_factory,probe_factory
            self._source_pin = source
            self._directory,self._identity = directory,(directory.stat().st_dev,directory.stat().st_ino)
            self._key_file,self._key = authority_key_file,_key(authority_key_file)
            self._environment,self._audience = environment_ref,audience_ref
            self._enabled,self._closed = execution_enabled,False
            self._activation_diagnostic = activation_diagnostic
            self._contract = DIAGNOSTIC_CONTRACT if activation_diagnostic else CONTRACT
            self._sampling_clock = self._sampling_clock_pin = sampling_clock or time.monotonic
            self._sampling_wait = self._sampling_wait_pin = sampling_wait or time.sleep
            self._runtime_samples: dict[str,list[dict[str,Any]]] = {}
            self._removal_samples: list[dict[str,Any]] = []
            self._preview: dict[str,Any] | None = None
            self._grant: dict[str,Any] | None = None
            self._children: dict[str,JwtRotationPhase] = {}
            self._clock,self._last_clock,self._clock_failed = lambda:int(time.time()),None,False
            self._pins = self._bindings()
            self._namespace = _digest(self._pins)
            self._result: dict[str,Any] | None = None
            self._execution_deadline: int | None = None
        except Exception:
            raise RuntimeError(_ERROR) from None

    def _bindings(self) -> dict[str,Any]:
        keys = [self._key,self.source._key,self.source.owner._witness,self.source.original.store._key,_key(self.source.original.key_file)]
        children = {}
        for name,spec in self.phases.items():
            if type(spec) is not JwtRotationPhaseSpec or type(spec.store) is not PersistentM4ExecutionStateStore or spec.store._read_only:
                raise ValueError
            _private_directory(spec.directory); require_ref(spec.scope_ref,"phase_scope")
            authority,execution = _key(spec.authority_key_file),_key(spec.store._key_path)
            if not hmac.compare_digest(execution,spec.store._key):
                raise ValueError
            keys.extend((authority,execution))
            children[name] = {"directory":str(spec.directory),"identity":[spec.directory.stat().st_dev,spec.directory.stat().st_ino],
                "authority_file":str(spec.authority_key_file),"authority":hashlib.sha256(authority).hexdigest(),
                "store":str(spec.store._path),"store_key_file":str(spec.store._key_path),"execution":hashlib.sha256(execution).hexdigest(),"scope":spec.scope_ref}
        if len(set(keys)) != 17 or len({spec.scope_ref for spec in self.phases.values()}) != 6:
            raise ValueError
        return {"contract":self._contract,"source":self.source._namespace,"session":self.source.owner._session_digest,
            "requester":self.source.owner._config.requester_digest,"transport":self.source.owner._config.transport_digest,
            "environment":self._environment,"audience":self._audience,"children":children,
            "directory":str(self._directory),"identity":list(self._identity),
            "authority_file":str(self._key_file),"authority":hashlib.sha256(self._key).hexdigest()}

    def _mac(self, purpose: str, body: object) -> str:
        return hmac.new(self._key,(self._contract+"\x00"+purpose+"\x00"+canonical_digest(body)).encode(),hashlib.sha256).hexdigest()

    def _live(self, *, execute: bool = False) -> None:
        self.source.live()
        if (self._closed or self.source is not self._source_pin or self._probe_factory is not self._probe_factory_pin
                or type(self._activation_diagnostic) is not bool
                or self._contract != (DIAGNOSTIC_CONTRACT if self._activation_diagnostic else CONTRACT)
                or self._sampling_clock is not self._sampling_clock_pin or self._sampling_wait is not self._sampling_wait_pin
                or not hmac.compare_digest(_key(self._key_file),self._key) or self._bindings() != self._pins
                or execute and (not self._enabled or not self.source._enabled)):
            raise RuntimeError(_ERROR)

    def _require_identity(self, requester: str, transport: str) -> None:
        if requester != self._pins["requester"] or transport != self._pins["transport"]:
            raise RuntimeError(_ERROR)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str,Any]:
        self._require_identity(requester_digest,transport_digest); self._live()
        if self._grant is not None:
            raise RuntimeError(_ERROR)
        current = self.source.current("user-create")
        now = self._now()
        result: dict[str,Any] = {"contract":self._contract,"policy_mode":"lab_auto","preview_ref":"jwt-rotation-preview-"+secrets.token_hex(16),
            "expires_at":now+300,"Current State":{"original_key_custody_verified":True,"jwt_user_absent":True,"digest":current.current_digest},
            "Proposed Changes":{"fixed_child_sequence":list(PHASES),"maximum_native_mutations":6,
                "owned_user_api_key_initialization":True,"generated_api_key_discarded":True,
                "overlap_submission_order":["new","old"],
                "claim_match":"exact","lease_minutes":10,"private_assertion_algorithm":"RS256","secret_acl_changes":False},
            "Expected State":{"original_key_restored":True,"owned_jwt_user_absent":True,"authentication_and_lease_effects_observed":True},
            "recovery":"unused_original_owned_restore_then_user_removal_only_no_native_replay",
            "device_write_executed":False}
        if self._activation_diagnostic:
            result["Proposed Changes"]["failed_overlap_path"] = "single_new_key_probe_then_original_restore"
            result["Proposed Changes"]["assertion_connection_policy"] = "new_verified_client_per_assertion"
            result["Proposed Changes"]["runtime_sample_offsets_after_poststate_ms"] = [0,1000,4000]
            result["Proposed Changes"]["maximum_authentication_requests"] = 32
            result["Proposed Changes"]["maximum_lease_checks"] = 64
            result["Expected State"]["rotation_accepted"] = False
        else:
            result["Proposed Changes"].update(assertion_connection_policy="new_verified_client_per_assertion",
                runtime_readiness_offsets_after_poststate_ms=[0,1000,4000],maximum_authentication_requests=32,
                maximum_lease_checks=64,post_removal_denial_offsets_ms=[0,1000,4000],
                unqualified_http401_is_revocation_evidence=False)
        result["summary_digest"] = canonical_digest(result)
        self._preview = result
        return dict(result)

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,Any]:
        self._require_identity(requester_digest,transport_digest); self._live(execute=True)
        p = self._preview
        if p is None or preview_ref != p["preview_ref"] or self._grant is not None or self._now()>=p["expires_at"]:
            raise RuntimeError(_ERROR)
        if p["summary_digest"] != canonical_digest({k:v for k,v in p.items() if k != "summary_digest"}):
            raise RuntimeError(_ERROR)
        body = {"namespace":self._namespace,"binding":self._pins,"preview":p,
            "authorization_ref":"jwt-rotation-auth-"+self._mac("authorization",p),"expires_at":p["expires_at"]}
        self._grant = {**body,"hmac":self._mac("grant",body)}
        with self._lock() as directory:
            self._write(directory,"grant.json",self._grant)
        return {"contract":self._contract,"policy_mode":"lab_auto","authorization_ref":body["authorization_ref"],"expires_at":body["expires_at"]}

    def _child(self, name: str, *, recovery: bool = False) -> None:
        self._live(execute=True)
        if (self._grant is None or self._execution_deadline is None or self._now()>=self._execution_deadline
                or name in self._children):
            raise RuntimeError(_ERROR)
        spec = self.phases[name]
        child = JwtRotationPhase(self.source,spec.store,phase=name,directory=spec.directory,
            authority_key_file=spec.authority_key_file,parent_digest=_digest(self._grant),
            environment_ref=self._environment,scope_ref=spec.scope_ref,audience_ref=self._audience,
            execution_enabled=True,recovery=recovery,deadline=self._execution_deadline)
        self._children[name] = child
        try:
            result = child.execute(*child.issue())
            if (result.outcome,result.verification) != ("succeeded","verified"):
                raise RuntimeError(_ERROR)
        finally:
            child.close()

    def _sample_authentication(self, phase: str) -> dict[str,bool]:
        if self.probe is None or phase not in {"overlap","cutover","restore"}:
            raise RuntimeError(_ERROR)
        start = last = self._sampling_clock()
        if type(start) not in {int,float} or not math.isfinite(start) or start < 0:
            raise RuntimeError(_ERROR)
        samples: list[dict[str,Any]] = []; self._runtime_samples[phase] = samples
        for offset in (0,1,4):
            self._live(execute=True)
            now = self._sampling_clock()
            if not math.isfinite(now) or now < last or now-start>30:
                raise RuntimeError(_ERROR)
            self._sampling_wait(max(0,start+offset-now))
            observed = self._sampling_clock()
            if not math.isfinite(observed) or observed < max(now,start+offset) or observed-start>30:
                raise RuntimeError(_ERROR)
            self._live(execute=True)
            if self._execution_deadline is None or self._now()>=self._execution_deadline:
                raise RuntimeError(_ERROR)
            sample = {"requested_offset_ms":offset*1000,"observed_offset_ms":round((observed-start)*1000),
                "old":self.probe.authenticate("old") is not None,"new":self.probe.authenticate("new") is not None}
            samples.append(sample); last = self._sampling_clock()
            if not math.isfinite(last) or last < observed:
                raise RuntimeError(_ERROR)
            expected = {"old":phase != "cutover","new":phase != "restore"}
            if not self._activation_diagnostic and all(sample[name] is value for name,value in expected.items()):
                break
        self.source.observe(key_phases=(phase,),user_present=True)
        return {name:samples[-1][name] for name in ("old","new")}

    def _observe_user_removal(self) -> None:
        if self._activation_diagnostic or self.probe is None:
            raise RuntimeError(_ERROR)
        start = last = self._sampling_clock()
        if not math.isfinite(start) or start < 0:
            raise RuntimeError(_ERROR)
        for offset in (0,1,4):
            self._live(execute=True)
            now = self._sampling_clock()
            if not math.isfinite(now) or now < last or now-start>30:
                raise RuntimeError(_ERROR)
            self._sampling_wait(max(0,start+offset-now));observed = self._sampling_clock()
            if not math.isfinite(observed) or observed < max(now,start+offset) or observed-start>30:
                raise RuntimeError(_ERROR)
            if self._execution_deadline is None or self._now()>=self._execution_deadline:
                raise RuntimeError(_ERROR)
            self.source.observe(key_phases=("restore",),user_present=False)
            observed = self._sampling_clock()
            if not math.isfinite(observed) or observed < max(now,start+offset) or observed-start>30:
                raise RuntimeError(_ERROR)
            first = len(self.probe.observations);unqualified = False
            try:
                denied = self.probe.authenticate("old") is None
            except JwtRotationAuthenticationError:
                records = [v for v in self.probe.observations[first:]if v.get("operation") == "assertion"]
                if (len(records) != 1 or records[0].get("stage") != "html_rejection"
                        or records[0].get("http_status") != 401 or records[0].get("json_content") is not False):
                    raise
                details = records[0].get("html_observation",{})
                if details and (details.get("captured_complete") is not True or any(details.get(name) for name in
                        ("lockout_language","rate_limit_language","login_form"))):
                    raise
                denied = False;unqualified = True
            self._removal_samples.append({"requested_offset_ms":offset*1000,
                "observed_offset_ms":round((observed-start)*1000),"qualified_denial":denied,"unqualified_http401":unqualified})
            if denied:
                self.source.observe(key_phases=("restore",),user_present=False)
                return
            last = self._sampling_clock()
            if not math.isfinite(last) or last < observed:
                raise RuntimeError(_ERROR)
        raise RuntimeError(_ERROR)

    def _cleanup(self) -> bool:
        """Use only unused restore/remove slots and original User ACK custody."""
        if not os.path.lexists(self.source._directory/"user-create.ack.json"):
            if os.path.lexists(self.source._directory/"user-create.claim.json"):
                return False
            try:
                self.source.observe(key_phases=("original",),user_present=False)
                return True
            except Exception:
                return False
        try:
            if os.path.lexists(self.source._directory/"user-remove.claim.json"):
                self.source.observe(key_phases=("restore",),user_present=False)
                return True
            current = self.source.current("restore",recovery=True)
            if current.key_phase in {"overlap","cutover"}:
                if "restore" in self._children:
                    return False
                self._child("restore",recovery=True)
            if "user-remove" in self._children:
                return False
            self._child("user-remove",recovery=True)
            return True
        except Exception:
            return False

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str,
            authorization_deadline: int | None = None) -> dict[str,Any]:
        self._require_identity(requester_digest,transport_digest); self._live(execute=True)
        if self._grant is None or authorization_ref != self._grant["authorization_ref"] or self._now()>=self._grant["expires_at"]:
            raise RuntimeError(_ERROR)
        if authorization_deadline is not None and (type(authorization_deadline) is not int or authorization_deadline<=self._now()):
            raise RuntimeError(_ERROR)
        self._execution_deadline = min(self._grant["expires_at"],authorization_deadline) if authorization_deadline is not None else self._grant["expires_at"]
        with self._lock() as directory:
            stored = self._read(directory,"grant.json")
            if stored != self._grant:
                raise RuntimeError(_ERROR)
            self._write(directory,"dispatch.json",{"namespace":self._namespace,"grant_digest":_digest(self._grant),
                "authorization_deadline":self._execution_deadline,"retry_allowed":False})
        stage = "prewrite_drift"; completed = cleanup = leases_denied = False
        observation: str | None = None
        overlap_authentication: dict[str,bool] | None = None
        single_new_key_authentication: dict[str,bool] | None = None
        try:
            assert self._preview is not None
            if self.source.current("user-create").current_digest != self._preview["Current State"]["digest"]:
                raise RuntimeError(_ERROR)
            stage = "protected_signers"
            self.probe = self._probe_factory()
            if (type(self.probe) is not JwtRotationAuthenticationProbe or not self.probe._enabled
                    or self.probe._binding.digest != self.source.binding.digest
                    or self.probe._fresh_assertion_clients is not True or self.probe._runtime_sampling is not True
                    or self.probe._keys.digest != self.source.keys.digest or self.probe._config != self.source.owner._config):
                raise RuntimeError(_ERROR)
            stage = "user-create"; self._child(stage)
            stage = "user-initialize"; self._child(stage)
            self.probe.__enter__()
            stage = "original_assertions"
            original = self.probe.authenticate("old")
            if original is None or self.probe.authenticate("new") is not None:
                raise RuntimeError(_ERROR)
            for case in ("wrong-issuer","wrong-audience","wrong-subject","expired"):
                if self.probe.authenticate("old",case=case) is not None:
                    raise RuntimeError(_ERROR)
            stage = "overlap"; self._child(stage)
            stage = "overlap_assertions"
            overlap_authentication = self._sample_authentication("overlap")
            if not all(overlap_authentication.values()) and not self._activation_diagnostic:
                raise RuntimeError(_ERROR)
            stage = "cutover"; self._child(stage)
            stage = "cutover_assertions"
            single_new_key_authentication = self._sample_authentication("cutover")
            if not self._activation_diagnostic and single_new_key_authentication != {"old":False,"new":True}:
                raise RuntimeError(_ERROR)
            observation = "still-valid" if self.probe.check(original) else "denied"
            stage = "restore"; self._child(stage)
            stage = "restore_assertions"
            if self._sample_authentication("restore") != {"old":True,"new":False}:
                raise RuntimeError(_ERROR)
            stage = "user-remove"; self._child(stage); cleanup = True
            stage = "lease_revocation"
            if not self._activation_diagnostic:
                self._observe_user_removal()
            leases_denied = bool(self.probe._leases) and all(self.probe.check(lease) is False for lease in self.probe._leases)
            if not leases_denied or self._activation_diagnostic and self.probe.authenticate("old") is not None:
                raise RuntimeError(_ERROR)
            if not self._activation_diagnostic:
                stage = "original_key_removal_readiness"
                self.source.owner.owned_state()
            completed = True
        except Exception:
            cleanup = self._cleanup()
            if cleanup and not leases_denied and self.probe is not None and self.probe._client is not None:
                try:
                    leases_denied = bool(self.probe._leases) and all(self.probe.check(lease) is False for lease in self.probe._leases)
                except Exception:
                    leases_denied = False
        finally:
            if completed:
                stage = "closure"
            try:
                self.close()
            except Exception:
                completed = False
        completed = completed and cleanup and leases_denied and self.source.owner.logout_verified
        result: dict[str,Any] = {"contract":self._contract,"outcome":"succeeded" if completed else "reconciliation_required",
            "verification":"verified" if completed else "unknown","idempotent_replay":False,
            "original_key_restored_and_user_absent":cleanup,"existing_old_lease_after_cutover":observation,
            "overlap_authentication":overlap_authentication,
            "all_issued_leases_denied_after_user_removal":leases_denied,"failure_stage":None if completed else stage,
            "native_phase_claims":sum(os.path.lexists(self.source._directory/(name+".claim.json")) for name in PHASES),
            "all_candidate_gates_closed":self._closed and not self._enabled and not self.source._enabled
                and all(not child._enabled for child in self._children.values()),
            "owner_logout_and_cookie_rejection":self.source.owner.logout_verified,
            "private_assertions_and_leases_cleared":self.probe is None or all(lease._closed and not lease._token for lease in self.probe._leases)}
        if self._activation_diagnostic:
            result.update(rotation_accepted=False,activation_discriminator_completed=completed,
                single_new_key_authentication=single_new_key_authentication,runtime_samples=self._runtime_samples)
        else:
            result["runtime_samples"] = self._runtime_samples
            result["post_removal_samples"] = self._removal_samples
        self._result = result
        return dict(result)

    def close(self) -> None:
        self._enabled = False; self._closed = True
        try:
            for child in self._children.values():
                child.close()
            if self.probe is not None:
                self.probe.close()
        finally:
            self.source.close(); self.source.owner.close()
