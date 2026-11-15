"""Inactive fixed Instruction quota PUT and original-ACK recovery adapter.

An execution kernel must hold operation_lock and supply independent authority.
This module does not register a Tool, load credentials, or grant shared-setting
authority. Unknown dispatches are consumed; restoration requires original proof.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import threading
import time
from typing import Any, Literal
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from . import secret_bulk_import_metadata as m
from . import target_lifecycle_dependencies as d
from .instruction_quota_contract import (
    InstructionQuotaState, InstructionQuotaTransition,
    _Private, _state_digest, build_instruction_quota_body, verify_instruction_quota_readback,
)
from .instruction_quota_http_reader import read_instruction_quota_context
from .instruction_resource_usage import InstructionResourceUsage
from .instruction_feature_contract import _require_digest, _digest, _fingerprint
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _ssl_context, _zeroize_mutable,
)

CONTRACT = "fortipam-700-build29-owned-instruction-quota-transfer-transport-v1"
_PATH = "/api/v2/cmdb/secret/setting"
_ERROR = "The private Instruction quota transport is unavailable."
_FILES = frozenset({phase + suffix for phase in ("allocate", "restore")
                   for suffix in (".claim.json", ".ack.json", ".result.json")} | {"allocate.m4.json", "quota.runtime.json"})


class InstructionQuotaTransportError(RuntimeError):
    """Categorical failure, including consumed or unknown dispatch outcomes."""

    def __init__(self, stage: str = "boundary") -> None:
        super().__init__(_ERROR)
        # Only fixed local stages reach this field, never exception messages.
        self.stage = stage


def _members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class FortiPamInstructionQuotaHttpTransport(_Private):
    """One independently gated phase in a prebound temporary quota cycle.

    A two-field PUT does not establish backend atomicity. Partial writes or
    missing ACK/readback consume the claim and require separate reconciliation.
    """
    __slots__ = ("_config", "_baseline", "_binding", "_phase", "_directory", "_directory_id",
                 "_key", "_namespace", "_enabled", "_clock", "_last_clock", "_clock_failed",
                 "_reader", "_factory", "_lock_owner", "_lock_id")
    _config: SecretMetadataHttpTransportConfig
    _baseline: InstructionQuotaState
    _binding: InstructionQuotaTransition
    _phase: Literal["allocate", "restore"]
    _directory: Path
    _directory_id: tuple[int, int]
    _key: bytes
    _namespace: str
    _enabled: bool
    _clock: Callable[[], int]
    _last_clock: int | None
    _clock_failed: bool
    _reader: Callable[..., tuple[InstructionQuotaState, InstructionResourceUsage]]
    _factory: Callable[..., http.client.HTTPSConnection]
    _lock_owner: int | None
    _lock_id: tuple[int, int] | None

    def __init__(self, config: SecretMetadataHttpTransportConfig, baseline: InstructionQuotaState,
                 binding: InstructionQuotaTransition, *, state_directory: Path,
                 cycle_nonce: str, state_key: bytes, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 state_reader: Callable[..., tuple[InstructionQuotaState, InstructionResourceUsage]] = read_instruction_quota_context,
                 connection_factory: Callable[..., http.client.HTTPSConnection] = http.client.HTTPSConnection) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(baseline) is not InstructionQuotaState or (baseline._quotas[3] != 0 or baseline._quotas[1] < 2)
                    or type(binding) is not InstructionQuotaTransition
                    or type(state_key) is not bytes or not 32 <= len(state_key) <= 4096
                    or type(execution_enabled) is not bool
                    or not isinstance(state_directory, Path) or not state_directory.is_absolute()
                    or ".." in state_directory.parts
                    or any(p.is_symlink() for p in (state_directory, *state_directory.parents))):
                raise ValueError
            _require_digest(cycle_nonce)
            config.__post_init__()
            origin = urlsplit(config.base_url)
            if (origin.scheme != "https" or not origin.hostname or origin.username is not None
                    or origin.password is not None or origin.path not in ("", "/")
                    or origin.query or origin.fragment):
                raise ValueError
            video, file, software, _ = baseline._quotas
            allocated = _state_digest(baseline, (video, file - 1, software, 1))
            expected_current = allocated if binding._phase == "restore" else baseline._state
            expected_target = baseline._state if binding._phase == "restore" else allocated
            if binding._current != expected_current or binding._expected != expected_target:
                raise ValueError
            info = state_directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            identity = (info.st_dev, info.st_ino)
            namespace = _digest([CONTRACT, cycle_nonce, baseline._state, str(state_directory), identity,
                config.base_url, hashlib.sha256(config.bearer_token.encode()).hexdigest(),
                hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest() if config.ca_file else None,
                hashlib.sha256(state_key).hexdigest()])
            values: dict[str, object] = {"_config":config, "_baseline":baseline, "_binding":binding,
                "_phase":binding._phase, "_directory":state_directory, "_directory_id":identity,
                "_key":state_key, "_namespace":namespace, "_enabled":execution_enabled,
                "_clock":clock or (lambda:int(time.time())), "_last_clock":None, "_clock_failed":False,
                "_reader":state_reader, "_factory":connection_factory, "_lock_owner":None, "_lock_id":None}
            for key, value in values.items():
                object.__setattr__(self,key,value)
        except Exception:
            raise InstructionQuotaTransportError("initialization") from None

    def _now(self) -> int:
        try:
            value = self._clock()
            if self._clock_failed or type(value) is not int or value < 0 or self._last_clock is not None and value < self._last_clock:
                raise ValueError
        except Exception:
            object.__setattr__(self,"_clock_failed",True)
            raise ValueError from None
        object.__setattr__(self,"_last_clock",value)
        return value

    def _directory_fd(self) -> int:
        fd = os.open(self._directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info = os.fstat(fd)
        if ((info.st_dev,info.st_ino)!=self._directory_id or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o700):
            os.close(fd)
            raise ValueError
        return fd

    @contextmanager
    def operation_lock(self, *, require_existing: bool = False) -> Iterator[None]:
        directory = descriptor = None
        acquired = False
        try:
            if type(require_existing) is not bool or self._lock_owner is not None:
                raise ValueError
            directory = self._directory_fd()
            flags = os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK
            if not require_existing:
                flags |= os.O_CREAT
            descriptor = os.open("operation.lock",flags,0o600,dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=0):
                raise ValueError
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            object.__setattr__(self,"_lock_owner",threading.get_ident())
            object.__setattr__(self,"_lock_id",(info.st_dev,info.st_ino))
            acquired = True
            self._locked()
            yield
        except InstructionQuotaTransportError:
            raise
        except Exception:
            raise InstructionQuotaTransportError("lock") from None
        finally:
            if acquired:
                object.__setattr__(self,"_lock_owner",None)
                object.__setattr__(self,"_lock_id",None)
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)

    def _locked(self) -> None:
        if self._lock_owner != threading.get_ident():
            raise ValueError
        fd = self._directory_fd()
        try:
            info = os.stat("operation.lock",dir_fd=fd,follow_symlinks=False)
            if (info.st_dev,info.st_ino)!=self._lock_id or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise ValueError
        finally:
            os.close(fd)

    def _seal(self, value: dict[str, Any]) -> str:
        return hmac.new(self._key,(CONTRACT+"\0"+_digest(value)).encode(),hashlib.sha256).hexdigest()

    def _write_once(self, name: str, payload: dict[str, Any]) -> None:
        self._locked()
        if name not in _FILES:
            raise ValueError
        value = {"namespace":self._namespace,"payload":payload}
        value["seal"] = self._seal(value)
        raw = bytearray(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode())
        directory = self._directory_fd()
        try:
            if not 0<len(raw)<=16384:
                raise ValueError
            fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,"wb") as output:
                output.write(raw);output.flush();os.fsync(output.fileno())
            os.fsync(directory)
        finally:
            _zeroize_mutable(raw)
            os.close(directory)

    def _read(self, name: str) -> dict[str, Any]:
        self._locked()
        if name not in _FILES:
            raise ValueError
        directory = self._directory_fd()
        descriptor = None
        raw = bytearray()
        try:
            descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=16384):
                raise ValueError
            with os.fdopen(descriptor,"rb",closefd=False) as source:
                raw = bytearray(source.read(16385))
            current = os.stat(name,dir_fd=directory,follow_symlinks=False)
            if len(raw)!=info.st_size or (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):
                raise ValueError
            value = json.loads(raw,object_pairs_hook=_members)
            if (type(value) is not dict or set(value)!={"namespace","payload","seal"}
                    or value["namespace"]!=self._namespace or type(value["payload"]) is not dict
                    or type(value["seal"]) is not str
                    or not hmac.compare_digest(value["seal"],self._seal({"namespace":value["namespace"],"payload":value["payload"]}))):
                raise ValueError
            return value["payload"]
        finally:
            _zeroize_mutable(raw)
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def _exists(self, name: str) -> bool:
        self._locked()
        fd = self._directory_fd()
        try:
            try:
                os.stat(name,dir_fd=fd,follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False
        finally:
            os.close(fd)

    def _claim(self, phase: str) -> dict[str, Any]:
        claim = self._read(phase+".claim.json")
        if (set(claim)!={"phase","baseline","binding","current","expected","plan",
                        "authorization","expires_at","anchors","usage"}
                or claim.get("phase")!=phase or claim.get("baseline")!=self._baseline._state
                or type(claim["expires_at"]) is not int or claim["expires_at"]<0
                or phase=="allocate" and claim["anchors"] is not None
                or phase=="restore" and (type(claim["anchors"]) is not dict
                    or set(claim["anchors"])!={"claim","ack","result"})):
            raise ValueError
        for key in ("binding","current","expected","plan","authorization","usage"):
            _require_digest(claim[key])
        if phase=="restore":
            for value in claim["anchors"].values():
                _require_digest(value)
        return claim

    def _ack(self, phase: str) -> dict[str, Any]:
        claim, ack = self._claim(phase), self._read(phase+".ack.json")
        if (set(ack)!={"claim","serial","method","http_status","response_digest"}
                or ack.get("claim")!=_digest(claim) or ack.get("serial")!=self._baseline._serial
                or ack.get("method")!="PUT" or type(ack.get("http_status")) is not int or ack["http_status"]!=200):
            raise ValueError
        _require_digest(ack["response_digest"])
        return ack

    def _original_allocate(self) -> dict[str, str]:
        claim, ack = self._claim("allocate"), self._ack("allocate")
        video, file, software, _ = self._baseline._quotas
        expected = _state_digest(self._baseline, (video, file - 1, software, 1))
        result = self._read("allocate.result.json")
        if (claim["current"]!=self._baseline._state or claim["expected"]!=expected
                or result!={"claim":_digest(claim),"ack":_digest(ack),"state":expected}):
            raise ValueError
        return {"claim":_digest(claim),"ack":_digest(ack),"result":_digest(result)}

    def _precondition_context(self) -> tuple[InstructionQuotaState, InstructionResourceUsage]:
        try:
            self._locked()
            if self._phase=="allocate":
                if any(self._exists(name) for name in _FILES if name!="quota.runtime.json"):
                    raise ValueError
            else:
                self._original_allocate()
                if any(self._exists("restore"+suffix) for suffix in (".claim.json",".ack.json",".result.json")):
                    raise ValueError
            current, usage = self._reader(self._config,serial_digest=self._baseline._serial)
            body = build_instruction_quota_body(self._binding,current,usage)
            _zeroize_mutable(body)
            return current, usage
        except Exception:
            raise InstructionQuotaTransportError("precondition") from None

    def inspect_precondition(self) -> InstructionQuotaState:
        """Verify full configuration and fresh usage without exposing capacity."""
        return self._precondition_context()[0]

    def dispatch(self, *, expected_current_digest: str, plan_digest: str, authorization_digest: str,
                 expires_at: int, before_send: Callable[[], None]) -> None:
        connection = response = None
        body = raw = bytearray()
        cleanup_failed = False
        stage = "authorization"
        try:
            self._locked()
            for digest in (expected_current_digest,plan_digest,authorization_digest):
                _require_digest(digest)
            if (not self._enabled or expected_current_digest!=self._binding._current
                    or type(expires_at) is not int or not self._now()<expires_at<=self._now()+60):
                raise ValueError
            deadline = min(expires_at,self._now()+min(30,self._config.timeout_seconds))

            def remaining() -> float:
                value = deadline-self._now()
                if value<=0:
                    raise ValueError
                return value

            before_send()
            remaining()
            context = _ssl_context(self._config)
            if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            origin = urlsplit(self._config.base_url)
            stage = "connect"
            connection = self._factory(origin.hostname,origin.port or 443,context=context,
                                       timeout=remaining())
            connection.connect()
            remaining()
            stage = "precondition"
            current, usage = self._precondition_context()
            body = build_instruction_quota_body(self._binding,current,usage)
            before_send()
            remaining()
            stage = "claim"
            anchors = self._original_allocate() if self._phase=="restore" else None
            claim = {"phase":self._phase,"baseline":self._baseline._state,"binding":self._binding.digest,
                "current":current._state,"expected":self._binding._expected,"plan":plan_digest,
                "authorization":authorization_digest,"expires_at":expires_at,"anchors":anchors,
                "usage":usage._state}
            self._write_once(self._phase+".claim.json",claim)
            remaining()
            if connection.sock is not None:
                connection.sock.settimeout(remaining())
            stage = "put"
            connection.request("PUT",_PATH,body=body,headers={"Authorization":"Bearer "+self._config.bearer_token,
                "Content-Type":"application/json","Accept":"application/json","Accept-Encoding":"identity",
                "Connection":"close","User-Agent":"fortipam-mcp-instruction-quota/1"})
            response = connection.getresponse()
            remaining()
            stage = "ack_validation"
            if (response.status!=200 or response.getheader("Content-Type","").split(";")[0].lower()!="application/json"
                    or response.getheader("Content-Encoding","identity") not in ("","identity")):
                raise ValueError
            raw = bytearray(262145)
            used = 0
            while True:
                remaining()
                if connection.sock is not None:
                    connection.sock.settimeout(remaining())
                with memoryview(raw)[used:] as view:
                    count = response.readinto(view)
                remaining()
                if type(count) is not int or count<0 or used+count>262144:
                    raise ValueError
                if not count:
                    break
                used+=count
            raw = _take_mutable_prefix(raw, used)
            fields = d._spans(raw)
            d._equal(raw,fields,{"version":"v7.0.0","build":29,"path":"secret","name":"setting",
                "http_method":"PUT","http_status":200,"status":"success","vdom":"root"})
            if "action" in fields:
                d._equal(raw,fields,{"action":""})
            serial = m._scalar(raw,fields["serial"])
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest()!=self._baseline._serial:
                raise ValueError
            if "error" in fields:
                error = m._scalar(raw,fields["error"])
                if error is not None and (type(error) is not int or error!=0):
                    raise ValueError
            remaining()
            start = _skip_json_space(raw,0)
            end = _json_value_end(raw,start)
            stage = "ack_persistence"
            self._write_once(self._phase+".ack.json",{"claim":_digest(claim),"serial":self._baseline._serial,
                "method":"PUT","http_status":200,"response_digest":_fingerprint(raw,(start,end))})
        except Exception:
            raise InstructionQuotaTransportError(stage) from None
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(raw)
            for resource in (response,connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        cleanup_failed = True
            if cleanup_failed:
                raise InstructionQuotaTransportError("cleanup") from None

    def inspect_postcondition(self) -> str:
        try:
            self._locked()
            claim, ack = self._claim(self._phase), self._ack(self._phase)
            if (claim["binding"]!=self._binding.digest or claim["current"]!=self._binding._current
                    or claim["expected"]!=self._binding._expected
                    or claim["anchors"]!=(self._original_allocate() if self._phase=="restore" else None)):
                raise ValueError
            current, usage = self._reader(self._config,serial_digest=self._baseline._serial)
            verify_instruction_quota_readback(self._binding,current,usage)
            result = {"claim":_digest(claim),"ack":_digest(ack),"state":current._state}
            name = self._phase+".result.json"
            if self._exists(name):
                if self._read(name)!=result:
                    raise ValueError
            else:
                self._write_once(name,result)
            return current._state
        except Exception:
            raise InstructionQuotaTransportError("postcondition") from None
