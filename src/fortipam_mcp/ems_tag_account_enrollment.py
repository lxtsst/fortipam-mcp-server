"""Default-off central-only initial Account enrollment with whole-append custody.

Only the two derived variables are appended. Credentials are never stored in
this metadata directory. Used enrollment retirement needs the later Account
recovery contract; this module only retires a provably unused registration.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
from threading import RLock
import time
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object, MaterialBindingStatus
from v4_planning.models import require_digest

from .ems_tag_account_contract import _generate_password, parameters_digest, variables
from .ems_tag_admin_contract import ProspectiveEmsTagManagerAccount
from .ems_tag_contract import _canonical
from .ems_tag_custody import _decode
from .ems_tag_identity_sources import EmsTagIdentitySources
from .ems_tag_role_fixture_custody import EmsRoleFixtureCustody
from .ldap_server_runtime import _key, _read
from .local_user_reset_material_source import _directory_identity, _write_once
from .secret_create_central_lab_provider import OwnerOnlyCentralLabSecretCreateEnvFileLoader, _read_owner_only_secret_env_file, _is_valid_utf8
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-central-account-enrollment-v1"
_ERROR = "The protected EMS account enrollment is unavailable."
_DOMAIN = b"ems-central-account-enrollment/v1\x00"
_NAMES = frozenset({"prepare.json", "append.claim.json", "append.ack.json", "material.used.json", "retire.claim.json", "retire.ack.json"})


class EmsAccountCentralEnrollment(_OpaqueC3Object):
    def __init__(self, sources: EmsTagIdentitySources, draft: ProspectiveEmsTagManagerAccount,
                 parent: EmsRoleFixtureCustody, *, requester_digest: str, env_file: Path,
                 directory: Path, witness_key_file: Path, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(sources) is not EmsTagIdentitySources or type(draft) is not ProspectiveEmsTagManagerAccount
                    or type(parent) is not EmsRoleFixtureCustody or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)):raise ValueError
            draft.__post_init__();require_digest(requester_digest, "ems_account_requester")
            self._sources, self._draft, self._parent, self._requester = sources, draft, parent, requester_digest
            self._owned = parent.require_recovery_source(sources, requester_digest)
            if draft.role_uid != self._owned.role_uid or draft.trusted_host != sources._transport._config.local_address + "/32":raise ValueError
            self._directory, self._key_file, self._env = Path(directory), Path(witness_key_file), Path(env_file)
            self._identity = _directory_identity(self._directory)
            self._key = _key(self._key_file)
            if (self._key in (sources._key, parent._key, parent._store._key)
                    or self._key_file.parent == self._directory or not self._env.is_absolute()
                    or self._env.name != "fortinet_lab_secrets.local.env" or self._env.parent.name != "secrets"
                    or self._env.parent.parent.name != "fortipam-local-inventory"
                    or self._env == self._key_file or self._env.is_relative_to(self._directory)):raise ValueError
            self._writer_lock = self._env.parent.parent / "inventory/fortipam-service-material-registration.local.lock"
            self._variables = variables(draft)
            self._loader = OwnerOnlyCentralLabSecretCreateEnvFileLoader(secret_env_path=self._env,
                username_variable_name=self._variables[0], password_variable_name=self._variables[1])
            self._clock = clock or (lambda: int(time.time()))
            self._enabled, self._closed, self._last = execution_enabled, False, -1
            self._lock = RLock()
            self._check_files()
        except Exception:raise ValueError(_ERROR) from None

    def _binding(self) -> dict[str, Any]:
        return dict(contract=CONTRACT, parameters=self._draft.parameters_digest, parent=self._owned.custody_digest,
            instance=self._sources._binding, requester=self._requester, env_file=str(self._env),
            variables=list(self._variables), directory=str(self._directory), directory_identity=list(self._identity),
            key_file=str(self._key_file))

    def _check_files(self) -> None:
        if (_directory_identity(self._directory) != self._identity or _key(self._key_file) != self._key
                or {p.name for p in self._directory.iterdir()} - _NAMES
                or self._parent.inspect_verified_original() != self._owned
                or self._loader._secret_env_path != self._env
                or (self._loader._username_variable_name, self._loader._password_variable_name) != tuple(name.encode() for name in self._variables)):raise ValueError
        for entry in self._directory.iterdir():
            info = entry.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):raise ValueError

    def _now(self) -> int:
        self._check_files();value = self._clock()
        if self._closed or type(value) is not int or value < 0 or value < self._last:raise ValueError
        self._last = value
        return value

    def _role_current(self) -> None:
        observed = self._sources._current
        if observed is None:raise ValueError
        self._sources.check_current(observed)
        if self._parent.require_recovery_source(self._sources, self._requester) != self._owned:raise ValueError
        roles = [row for row in observed.full_scope._role_details if row._uid == self._owned.role_uid]
        if (observed.full_scope.digest != self._owned.created_scope_digest or len(roles) != 1
                or roles[0].digest != self._owned.role_digest or not roles[0].matches_proposal(self._parent._draft)
                or observed.full_scope.role_is_referenced(self._owned.role_uid)):raise ValueError

    def _mac(self, purpose: str, value: bytes | bytearray | memoryview) -> str:
        result = hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00", hashlib.sha256);result.update(value)
        return result.hexdigest()

    def _write(self, name: str, value: dict[str, Any]) -> None:
        self._check_files()
        if name not in _NAMES:raise ValueError
        body = dict(binding=self._binding(), value=value)
        raw = bytearray(_canonical(dict(body=body, signature=self._mac(name, _canonical(body)))))
        try:_write_once(self._directory, self._identity, name, raw)
        finally:_zeroize_mutable(raw)
        if self._record(name) != value:raise ValueError

    def _record(self, name: str) -> dict[str, Any]:
        self._check_files()
        return self._read_record(name)

    def _read_record(self, name: str) -> dict[str, Any]:
        """Read one signed record inside an already checked file boundary."""
        if name not in _NAMES:raise ValueError
        raw = _read(self._directory / name, 65536)
        try:
            packet = _decode(raw)
            if type(packet) is not dict or set(packet) != {"body", "signature"}:raise ValueError
            body = packet["body"]
            if (type(body) is not dict or set(body) != {"binding", "value"} or body["binding"] != self._binding()
                    or type(body["value"]) is not dict or type(packet["signature"]) is not str
                    or not hmac.compare_digest(packet["signature"], self._mac(name, _canonical(body)))):raise ValueError
            return body["value"]
        finally:_zeroize_mutable(raw)

    @staticmethod
    def _version(info: os.stat_result) -> tuple[int, ...]:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):raise ValueError
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def _read_env(self) -> tuple[bytearray, tuple[int, ...]]:
        # SMB path-stat timestamps may be refreshed by opening the same file.
        # Bind stable descriptor metadata and re-open the path to reject drift.
        descriptor = os.open(self._env, os.O_RDONLY | os.O_NOFOLLOW)
        raw = bytearray()
        try:
            before = self._version(os.fstat(descriptor))
            raw = _read_owner_only_secret_env_file(self._env)
            if before != self._version(os.fstat(descriptor)) or len(raw) != before[2] or len(raw) > 262144:raise ValueError
            current = os.open(self._env, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                if self._version(os.fstat(current)) != before:raise ValueError
            finally:os.close(current)
            return raw, before
        except Exception:_zeroize_mutable(raw);raise
        finally:os.close(descriptor)

    def _prepare(self, *, live: bool = True) -> dict[str, Any]:
        value = self._record("prepare.json")
        if (set(value) != {"reference", "created_at", "expires_at", "original_identity", "original_length", "original_mac"}
                or type(value["reference"]) is not str or re.fullmatch(r"ems-account-material-[a-f0-9]{48}", value["reference"]) is None
                or type(value["created_at"]) is not int or type(value["expires_at"]) is not int
                or not 0 <= value["created_at"] < value["expires_at"] or value["expires_at"] != value["created_at"] + 1800
                or type(value["original_identity"]) is not list or len(value["original_identity"]) != 2
                or any(type(x) is not int or x < 0 for x in value["original_identity"])
                or type(value["original_length"]) is not int or not 0 < value["original_length"] <= 262144):raise ValueError
        require_digest(value["original_mac"], "ems_account_env")
        if live and not value["created_at"] <= self._now() < value["expires_at"]:raise ValueError
        return value

    @property
    def reference(self) -> str:
        return str(self._prepare()["reference"])

    @property
    def parameters_digest(self) -> str:
        return parameters_digest(self._draft, self.reference, self._owned.custody_digest)

    def prepare_once(self) -> str:
        raw = bytearray()
        try:
            with self._lock:
                now = self._now();self._role_current()
                if any(self._directory.iterdir()):raise ValueError
                raw, info = self._read_env()
                if not _is_valid_utf8(raw) or 0 in raw or 13 in raw or not raw.endswith(b"\n"):raise ValueError
                names: set[bytes] = set();start = 0
                while start < len(raw):
                    end = raw.find(b"\n", start)
                    if end < start:raise ValueError
                    if end > start and raw[start] != 35:
                        equals = raw.find(b"=", start, end)
                        name = bytes(raw[start:equals]) if equals > start else b""
                        if re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", name) is None or name in names:raise ValueError
                        names.add(name)
                    start = end + 1
                if any(name.encode() in names for name in self._variables):raise ValueError
                self._write("prepare.json", dict(reference="ems-account-material-" + secrets.token_hex(24), created_at=now, expires_at=now + 1800,
                    original_identity=list(info[:2]), original_length=len(raw), original_mac=self._mac("original-env", raw)))
                return self.reference
        except Exception:self._closed = True;raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def _take_writer(self, reference: str) -> tuple[int, tuple[int, int]]:
        fd = os.open(self._writer_lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600);os.write(fd, reference.encode());os.fsync(fd)
            info = os.fstat(fd)
            return fd, (info.st_dev, info.st_ino)
        except Exception:os.close(fd);raise

    def _release_writer(self, writer: tuple[int, tuple[int, int]] | None) -> None:
        if writer is None:return
        fd, identity = writer
        try:
            info = self._writer_lock.lstat()
            if (info.st_dev, info.st_ino) != identity or info.st_uid != os.getuid():raise ValueError
            self._writer_lock.unlink()
        finally:os.close(fd)

    def _owned_tail(self, raw: bytearray, info: tuple[int, ...], prepare: dict[str, Any], claim: dict[str, Any]) -> None:
        if (set(claim) != {"reference", "tail_length", "tail_mac"} or claim["reference"] != prepare["reference"]
                or type(claim["tail_length"]) is not int or not 1 <= claim["tail_length"] <= 1024
                or list(info[:2]) != prepare["original_identity"]
                or len(raw) != prepare["original_length"] + claim["tail_length"]):raise ValueError
        require_digest(claim["tail_mac"], "ems_account_append")
        cut = prepare["original_length"]
        with memoryview(raw) as view:
            if (not hmac.compare_digest(self._mac("original-env", view[:cut]), prepare["original_mac"])
                    or not hmac.compare_digest(self._mac("whole-append", view[cut:]), claim["tail_mac"])):raise ValueError

    def register_once(self) -> None:
        raw = password = tail = bytearray();writer = None
        try:
            with self._lock:
                if not self._enabled:raise ValueError
                prepare = self._prepare();self._role_current();writer = self._take_writer(str(prepare["reference"]))
                raw, info = self._read_env()
                if (list(info[:2]) != prepare["original_identity"] or len(raw) != prepare["original_length"]
                        or self._mac("original-env", raw) != prepare["original_mac"]):raise ValueError
                password = _generate_password()
                tail = bytearray(self._variables[0].encode() + b"=" + self._draft._metadata_body["name"].encode() + b"\n" + self._variables[1].encode() + b"=")
                tail.extend(password);tail.extend(b"\n")
                self._write("append.claim.json", dict(reference=prepare["reference"], tail_length=len(tail), tail_mac=self._mac("whole-append", tail)))
                self._role_current();self._prepare()
                fd = os.open(self._env, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                try:
                    if self._version(os.fstat(fd)) != info:raise ValueError
                    if os.write(fd, tail) != len(tail):raise ValueError
                    os.fsync(fd)
                finally:os.close(fd)
                check, after = self._read_env()
                try:self._owned_tail(check, after, prepare, self._record("append.claim.json"))
                finally:_zeroize_mutable(check)
                if self._loader.validate_prebound() is not MaterialBindingStatus.AVAILABLE:raise ValueError
                self._write("append.ack.json", dict(reference=prepare["reference"], claim_digest=canonical_digest(self._record("append.claim.json")), registered_at=self._now()))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None
        finally:
            for value in (raw, password, tail):_zeroize_mutable(value)
            self._release_writer(writer)

    def check_registered(self, *, live: bool = True) -> None:
        raw = bytearray()
        try:
            if type(live) is not bool:raise ValueError
            prepare = self._prepare(live=live)
            if (self._directory / "retire.claim.json").exists():raise ValueError
            # Preparation checks the file boundary; verify the remaining signed
            # records locally, then recheck that boundary after the central read.
            claim = self._read_record("append.claim.json");ack = self._read_record("append.ack.json")
            if (set(ack) != {"reference", "claim_digest", "registered_at"} or ack["reference"] != prepare["reference"]
                    or ack["claim_digest"] != canonical_digest(claim) or type(ack["registered_at"]) is not int
                    or not prepare["created_at"] <= ack["registered_at"] < prepare["expires_at"]):raise ValueError
            raw, info = self._read_env();self._owned_tail(raw, info, prepare, claim)
            if self._loader.validate_prebound() is not MaterialBindingStatus.AVAILABLE:raise ValueError
            self._check_files()
        except Exception:raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def retire_unused_once(self) -> None:
        raw = bytearray();writer = None
        try:
            with self._lock:
                if not self._enabled or (self._directory / "material.used.json").exists():raise ValueError
                self._role_current();prepare = self._prepare(live=False)
                ack = self._record("append.ack.json");claim = self._record("append.claim.json")
                if ack["claim_digest"] != canonical_digest(claim):raise ValueError
                writer = self._take_writer(str(prepare["reference"]));raw, info = self._read_env();self._owned_tail(raw, info, prepare, claim)
                if (self._directory / "material.used.json").exists():raise ValueError
                self._write("retire.claim.json", dict(reference=prepare["reference"], original_length=prepare["original_length"], unused=True))
                fd = os.open(self._env, os.O_WRONLY | os.O_NOFOLLOW)
                try:
                    if self._version(os.fstat(fd)) != info:raise ValueError
                    os.ftruncate(fd, prepare["original_length"]);os.fsync(fd)
                finally:os.close(fd)
                check, after = self._read_env()
                try:
                    if (list(after[:2]) != prepare["original_identity"] or len(check) != prepare["original_length"]
                            or self._mac("original-env", check) != prepare["original_mac"]):raise ValueError
                finally:_zeroize_mutable(check)
                if self._loader.validate_prebound() is not MaterialBindingStatus.UNAVAILABLE:raise ValueError
                self._write("retire.ack.json", dict(reference=prepare["reference"], original_prefix_restored=True))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw);self._release_writer(writer)

    def close(self) -> None:
        with self._lock:self._closed, self._enabled = True, False
