"""One fixed Windows Launcher/hash association and verified restoration.

Owned providers are read-only prerequisites, never alternative mutation routes.
No caller supplies a name, path, software, payload or executable parameter.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from .client_integrity_http_transport import (
    FortiPamNativeClientIntegrityHttpTransport, NativeHashClientIntegrityBinding,
    _ACK_FIELDS, _PATH as SOFTWARE_PATH, _TYPES, _digest,
)
from .launcher_clone_http_transport import (
    FortiPamLauncherCloneHttpTransport, PuttyLauncherWindowsBinding,
    _private_parent, _read_private,
)
from .putty_launcher_windows_http_contract import (
    compile_native_windows_putty_association_body,
    compile_native_windows_putty_association_restore_body,
)
from .secret_metadata_http_transport import _ssl_context, _zeroize_mutable

CONTRACT = "fortipam_v4_putty_integrity_association_700_transport_v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE = "The fixed Windows Client Integrity association is unavailable."


class PuttyIntegrityAssociationTransportError(RuntimeError):
    """Stable failure without configuration, identifiers or material."""


@dataclass(frozen=True, slots=True, repr=False)
class PuttyIntegrityAssociationBinding:
    launcher_binding_digest: str
    software_binding_digest: str
    associated_configuration_digest: str

    def __post_init__(self) -> None:
        if any(type(v) is not str or _DIGEST.fullmatch(v) is None for v in (
            self.launcher_binding_digest, self.software_binding_digest, self.associated_configuration_digest,
        )):
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE)

    @property
    def digest(self) -> str:
        return _digest({"contract":CONTRACT, **{k:getattr(self,k) for k in self.__slots__}})


def load_putty_integrity_association_binding(path: Path) -> PuttyIntegrityAssociationBinding:
    try:
        value = _read_private(path)
        if set(value) != {"contract", *PuttyIntegrityAssociationBinding.__slots__} or value.pop("contract") != CONTRACT:
            raise ValueError
        return PuttyIntegrityAssociationBinding(**value)
    except Exception:
        raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE) from None


class PuttyIntegrityAssociationHttpTransport:
    """A bound one-field PUT; fresh full-state checks precede and follow dispatch."""

    def __init__(self, launcher: FortiPamLauncherCloneHttpTransport,
                 software: FortiPamNativeClientIntegrityHttpTransport,
                 binding: PuttyIntegrityAssociationBinding, state_directory: Path,
                 authorization_key_file: Path, *, association_enabled: bool = False,
                 restore_enabled: bool = False, clock: Callable[[], int] | None = None,
                 client_factory: Callable[..., Any] | None = None) -> None:
        try:
            if (type(launcher) is not FortiPamLauncherCloneHttpTransport
                    or type(software) is not FortiPamNativeClientIntegrityHttpTransport
                    or type(launcher._binding) is not PuttyLauncherWindowsBinding
                    or type(software._binding) is not NativeHashClientIntegrityBinding
                    or type(binding) is not PuttyIntegrityAssociationBinding
                    or type(association_enabled) is not bool or type(restore_enabled) is not bool
                    or launcher._clone_enabled or launcher._recovery_enabled or software._create or software._recovery
                    or launcher._config != software._config
                    or launcher._binding.digest != binding.launcher_binding_digest
                    or software._binding.digest != binding.software_binding_digest
                    or launcher._binding.device_identity_digest != software._binding.device_identity_digest
                    or launcher._binding.executable_sha256 != software._binding.executable_sha256
                    or state_directory in {launcher._state, software._state}):
                raise ValueError
            _private_parent(state_directory / "associate.claim.json")
            _private_parent(authorization_key_file)
            fd = os.open(authorization_key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd,"rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 32):
                    raise ValueError
                key = stream.read(33)
            if len(key) != 32 or hmac.compare_digest(key, software._key):
                raise ValueError
        except Exception:
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE) from None
        self._launcher, self._software, self._binding, self._state, self._key = launcher, software, binding, state_directory, key
        self._association, self._restore, self._clock = association_enabled, restore_enabled, clock or (lambda:int(time.time()))
        self._factory = client_factory
        self._namespace = _digest({"origin":launcher._config.base_url,"binding":binding.digest})

    def _record(self, direction: str, state: str, **fields: object) -> dict[str, Any]:
        return {"contract":CONTRACT,"namespace":self._namespace,"direction":direction,"state":state,**fields}

    def _save(self, filename: str, value: Mapping[str, object]) -> None:
        path = self._state / filename; _private_parent(path)
        value = dict(value)
        value["mac"] = hmac.new(self._key,b"putty-integrity-association-record:" +
            json.dumps(value,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
        parent = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(path.name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,"w") as stream:
                json.dump(value,stream,sort_keys=True); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    def _load(self, filename: str, direction: str, state: str) -> dict[str, Any]:
        value = _read_private(self._state / filename); signature = value.pop("mac")
        expected = hmac.new(self._key,b"putty-integrity-association-record:" +
            json.dumps(value,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
        if (type(signature) is not str or not hmac.compare_digest(signature,expected)
                or any(value.get(k) != v for k,v in self._record(direction,state).items())):
            raise ValueError
        return value

    def intent_consumed(self, *, recovery: bool) -> bool:
        if type(recovery) is not bool:
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE)
        return os.path.lexists(self._state / (("restore" if recovery else "associate") + ".intent.json"))

    def reserve_intent(self, requester_digest: str, authorization_digest: str, *, expires_at: int, recovery: bool) -> None:
        try:
            now = self._clock()
            if (type(recovery) is not bool or type(now) is not int or type(expires_at) is not int
                    or not now < expires_at <= now + 600 or any(type(v) is not str or _DIGEST.fullmatch(v) is None
                    for v in (requester_digest, authorization_digest))):
                raise ValueError
            self.inspect(recovery=recovery)
            refreshed = self._clock()
            if type(refreshed) is not int or not now <= refreshed < expires_at:
                raise ValueError
            direction = "restore" if recovery else "associate"
            self._save(direction + ".intent.json",self._record(direction,"intent_reserved",
                requester_digest=requester_digest,authorization_digest=authorization_digest,issued_at=now,expires_at=expires_at))
        except Exception:
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE) from None

    def _guard(self, direction: str) -> None:
        if not (self._restore if direction == "restore" else self._association):
            raise ValueError
        record = self._load(direction + ".intent.json",direction,"intent_reserved"); now = self._clock()
        if (type(now) is not int or type(record.get("issued_at")) is not int or type(record.get("expires_at")) is not int
                or not record["issued_at"] <= now < record["expires_at"]):
            raise ValueError

    def _ownership(self) -> str:
        launcher, software = self._launcher, self._software
        for filename,state in (("clone.claim.json","reserved"),("clone.verified.json","verified")):
            if _read_private(launcher._state / filename) != launcher._record("clone",state):
                raise ValueError
        if any(os.path.lexists(launcher._state / n) for n in ("recover.intent.json","recover.claim.json","recover.verified.json")):
            raise ValueError
        software._load("create.claim.json","create","reserved")
        verified = software._load("create.verified.json","create","verified")
        digest = verified.get("configuration_digest")
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ValueError
        if any(os.path.lexists(software._state / n) for n in ("recover.intent.json","recover.claim.json","recover.verified.json")):
            raise ValueError
        return digest

    def _software_state(self, *, associated: bool, owned_digest: str) -> None:
        software = self._software; buffers: list[bytearray] = []
        def read(path: str) -> bytearray:
            value = software._request("GET",path); buffers.append(value); return value
        try:
            collection = read(SOFTWARE_PATH + "?count=200&start=0&with_meta=true&vdom=root")
            rows, selected = software._collection(collection)
            if selected is None:
                raise ValueError
            collection_payload = software._project(collection,selected)
            direct = read(software._detail); left,right = software._spans(direct)["results"]
            if direct[left] == 91:
                records = software._rows(direct,left,right)
                if len(records) != 1:
                    raise ValueError
                left,right = records[0]
            payload = software._project(direct,(left,right))
            if software._readback(payload).configuration_digest != software._readback(collection_payload).configuration_digest:
                raise ValueError
            row = payload["results"]
            if (type(row.get("q_ref")) is not int or row["q_ref"] != int(associated)
                    or _digest(row) != software._readback(payload).configuration_digest
                    or software._object_type(read(_TYPES)) != software._binding.object_type):
                raise ValueError
            for value in (collection_payload, payload):
                serial = value.get("serial")
                if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != software._binding.device_identity_digest:
                    raise ValueError
            normalized = deepcopy(row); normalized["q_ref"] = 0
            if _digest(normalized) != owned_digest:
                raise ValueError
            del rows[software._binding.software_name]
            if _digest(rows) != software._binding.visible_collection_digest:
                raise ValueError
            # Before attaching and after detaching, retain the qualified complete
            # zero-reference/empty-usage check. Positive usage grammar is not inferred.
            if not associated:
                _, digest = software._snapshot(True)
                if digest != owned_digest:
                    raise ValueError
        finally:
            for buffer in buffers:
                _zeroize_mutable(buffer)

    def _snapshot(self, *, associated: bool) -> dict[str, object]:
        owned_digest = self._ownership()
        launcher, software = self._launcher, self._software; b = launcher._binding
        assert isinstance(b,PuttyLauncherWindowsBinding)
        launcher._source()
        code,payload = launcher._request("GET",launcher._path(b.destination_name) + "?with_meta=true&vdom=root")
        if code != 200:
            raise ValueError
        if associated:
            body = compile_native_windows_putty_association_restore_body(payload,
                launcher_name=b.destination_name,software_name=software._binding.software_name,
                application=b.application,baseline_configuration_digest=b.clone_digest,
                expected_associated_configuration_digest=self._binding.associated_configuration_digest)
        else:
            body = compile_native_windows_putty_association_body(payload,
                launcher_name=b.destination_name,software_name=software._binding.software_name,
                application=b.application,baseline_configuration_digest=b.clone_digest)
            expected = deepcopy(payload["results"])
            if type(expected) is list:
                expected = expected[0]
            expected["os_app"][0]["client-software"] = software._binding.software_name
            if _digest(expected) != self._binding.associated_configuration_digest:
                raise ValueError
        row = payload["results"]
        if type(row) is list:
            row = row[0]
        launcher._usage_empty(row["q_type"])
        rows = launcher._collection()
        if b.destination_name not in rows:
            raise ValueError
        del rows[b.destination_name]
        if _digest(rows) != b.collection_digest:
            raise ValueError
        self._software_state(associated=associated,owned_digest=owned_digest)
        return body

    def inspect(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool:
                raise ValueError
            direction = "restore" if recovery else "associate"
            if os.path.lexists(self._state / (direction + ".claim.json")):
                raise ValueError
            if recovery:
                self._load("associate.claim.json","associate","reserved")
                verified = self._load("associate.verified.json","associate","verified")
                if verified.get("configuration_digest") != self._binding.associated_configuration_digest:
                    raise ValueError
            elif any(os.path.lexists(self._state / n) for n in ("associate.verified.json","restore.intent.json","restore.claim.json")):
                raise ValueError
            self._snapshot(associated=recovery)
            return {"owned_windows_launcher_verified":True,"owned_hash_software_verified":True,
                    "complete_expected_state_verified":True,"unrelated_visible_state_preserved":True,
                    "launcher_reported_usage_empty":True,"device_write_executed":False}
        except Exception:
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE) from None

    def _put(self, direction: str, body: Mapping[str, object]) -> None:
        import httpx
        config = self._launcher._config; binding = self._launcher._binding
        assert isinstance(binding,PuttyLauncherWindowsBinding)
        raw = bytearray()
        try:
            self._guard(direction)
            path = self._launcher._path(binding.destination_name) + "?vdom=root"
            factory = self._factory or httpx.Client
            with factory(base_url=config.base_url,verify=_ssl_context(config),timeout=config.timeout_seconds,
                         trust_env=False,follow_redirects=False) as client:
                self._guard(direction)
                with client.stream("PUT",path,headers={"Authorization":"Bearer " + config.bearer_token,
                    "Content-Type":"application/json","Accept":"application/json","Accept-Encoding":"identity",
                    "Cache-Control":"no-cache, no-store"},content=json.dumps(body,separators=(",",":")).encode()) as response:
                    status = response.status_code
                    is_json = "json" in response.headers.get("content-type","")
                    if is_json:
                        for chunk in response.iter_bytes():
                            if len(raw) + len(chunk) > 1_048_576:
                                raise ValueError
                            raw.extend(chunk)
            valid = False
            try:
                # The span parser rejects duplicate root members before decode.
                fields = self._software._spans(raw)
                value = json.loads(raw)
                fixed = {"version":"v7.0.0","build":29,"http_method":"PUT","http_status":200,
                         "path":"secret","name":"launcher","vdom":"root"}
                serial = value.get("serial")
                valid = (status == 200 and is_json and set(fields) <= _ACK_FIELDS
                    and all(type(value.get(k)) is type(v) and value[k] == v for k,v in fixed.items())
                    and value.get("status") in {"success","OK"} and type(serial) is str
                    and hashlib.sha256(serial.encode()).hexdigest() == binding.device_identity_digest
                    and ("mkey" not in value or value["mkey"] == binding.destination_name)
                    and ("action" not in value or value["action"] == "")
                    and ("error" not in value or type(value["error"]) is int and value["error"] == 0)
                    and ("revision_changed" not in value or value["revision_changed"] is True))
                for key in ("revision","old_revision"):
                    if key in value and (type(value[key]) is not str or len(value[key]) > 255
                        or any(ord(c) < 32 or ord(c) == 127 for c in value[key])):
                        valid = False
            except Exception:
                valid = False
            self._save(direction + ".response.json",self._record(direction,"response_observed",
                http_status=status,json_content_type=is_json,strict_acknowledgement_verified=valid))
            if not valid:
                raise ValueError
        finally:
            _zeroize_mutable(raw)

    def execute(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool:
                raise ValueError
            direction = "restore" if recovery else "associate"
            self._guard(direction)
            self.inspect(recovery=recovery)
            self._save(direction + ".claim.json",self._record(direction,"reserved"))
            # Fresh full-state compiler checks after claim; drift consumes without PUT.
            body = self._snapshot(associated=recovery)
            self._guard(direction)
            self._put(direction,body)
            self._snapshot(associated=not recovery)
            self._save(direction + ".verified.json",self._record(direction,"verified",
                configuration_digest=self._launcher._binding.clone_digest if recovery else self._binding.associated_configuration_digest))
            return {"verified":True,"software_reference_present":not recovery,
                    "complete_expected_state_verified":True,"unrelated_visible_state_preserved":True,
                    "client_launched":False,"hash_enforcement_verified":False}
        except Exception:
            raise PuttyIntegrityAssociationTransportError(_UNAVAILABLE) from None
