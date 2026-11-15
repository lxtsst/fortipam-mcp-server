"""Private build-29 sources and independently signed, exact lab qualification.

Nothing here signs qualification or registers an action. A protected source
authority must attest the exact binding and M4 plan after its own qualification
checks. An unsigned configuration file or a successful login is insufficient.
The producer is invoked only after the fixed runner validates the intent chain.
"""

from __future__ import annotations

from collections.abc import Mapping

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import re
import selectors
import shlex
import subprocess
import time
from threading import Lock
from typing import TYPE_CHECKING, cast

from v4_planning import M4AdapterDenied
from v4_planning.models import canonical_digest, require_digest, require_ref

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .approval_and_observe_projection_source import ApprovalAndObserveBinding
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29MutationBinding,
    SecretApprovalBuild29WebFieldsBinding, SecretApprovalBuild29LinuxFieldsBinding, qualify_secret_approval_build29_put_ack,
)
from .secret_approval_build29_m4_composition import SecretApprovalBuild29PrivateTransition
from .secret_approval_build29_m4_runtime import secret_approval_build29_transport_binding_digest
from .secret_approval_build29_metadata_reader import SecretApprovalBuild29ProfileReader
from .secret_approval_build29_projection_source import _reject_constant, _unique_members
from .secret_metadata_http_transport import _zeroize_mutable, _record
from .folder_acl_live_workflow import _relations, _FOLDER_PERMISSIONS, _SECRET_PERMISSIONS
from .folder_rename_live_workflow import _canonical_acl_projection
from .secret_create_central_lab_provider import _validated_variable_name, _ascii_identifier, _dotenv_value_range

if TYPE_CHECKING:
    from .secret_approval_build29_private_sources import SecretApprovalBuild29PrivateSources


_UNAVAILABLE = "Protected build-29 approval sources are unavailable."
QUALIFICATION_CONTRACT = "fortipam-700-build29-exact-lab-qualification-v1"
QUALIFICATION_SCOPE = "targetless-web-account-empty-totp-single-tier-admin"
LINUX_QUALIFICATION_CONTRACT = "fortipam-700-build29-exact-linux-lab-qualification-v1"
LINUX_QUALIFICATION_SCOPE = "fixed-linux-target-empty-totp-single-tier-admin"
_LINUX_QUALIFICATION_DOMAIN = b"fortipam-700-build29-exact-linux-lab-qualification-v1\x00"
_QUALIFICATION_DOMAIN = b"fortipam-700-build29-exact-lab-qualification-v1\x00"


class SecretApprovalBuild29RuntimeProviderError(RuntimeError):
    """A stable refusal with no material, source selectors or parser details."""


def _read_private_buffer(path: Path, limit: int, *, public_pin: bool = False) -> bytearray:
    """Open every path component without following symlinks; never decode material."""
    value = bytearray(limit + 1)
    directory: int | None = None
    descriptor: int | None = None
    try:
        if not path.is_absolute() or ".." in path.parts or not 0 < limit <= 16384:
            raise ValueError
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        initial = os.fstat(descriptor)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.getuid()
                or (stat.S_IMODE(initial.st_mode) & 0o022 if public_pin else stat.S_IMODE(initial.st_mode) != 0o600)
                or not 0 < initial.st_size <= limit):
            raise ValueError
        count = os.readv(descriptor, [value])
        final = os.fstat(descriptor)
        if (count != initial.st_size or os.read(descriptor, 1)
                or (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
                != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)):
            raise ValueError
        del value[count:]
        return value
    except Exception:
        _zeroize_mutable(value)
        raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


class OwnerOnlySecretApprovalBuild29UsernameSource:
    """Fresh mutable Username bytes; association is checked against the fixed GET.

    The source does not infer account material from redacted metadata. The fixed
    Web projector compares these bytes with the retained Username slot before
    dispatch, and the transport erases their complete backing buffer on exit.
    """

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or ".." in path.parts:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE)
        self._path = path

    def __repr__(self) -> str:
        return "<OwnerOnlySecretApprovalBuild29UsernameSource protected>"

    def read_span(self) -> memoryview:
        raw = _read_private_buffer(self._path, 256)
        try:
            # No newline trimming, text decoding, environment interpolation or fallback.
            if not raw or any(value < 32 or value == 127 for value in raw):
                raise ValueError
            return memoryview(raw)
        except Exception:
            _zeroize_mutable(raw)
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None


class OwnerOnlySecretApprovalBuild29EnvUsernameSource:
    """Read only the statically selected Username from the original protected env.

    Never evaluates shell syntax, extracts another value, or creates a new file.
    The whole file buffer is erased before returning the selected mutable span.
    """

    def __init__(self, path: Path, *, username_variable: str) -> None:
        try:
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError
            self._variable = _validated_variable_name(username_variable)
            self._path = path
        except Exception:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None

    def __repr__(self) -> str:
        return "<OwnerOnlySecretApprovalBuild29EnvUsernameSource protected>"

    def read_span(self) -> memoryview:
        raw, selected = bytearray(), bytearray()
        try:
            raw = _read_private_buffer(self._path, 16384)
            if 0 in raw or 13 in raw:
                raise ValueError
            seen: set[bytes] = set()
            start = 0
            while start < len(raw):
                end = raw.find(b"\n", start)
                if end < 0:
                    end = len(raw)
                if end != start and raw[start] != 35:
                    equals = raw.find(b"=", start, end)
                    if equals <= start:
                        raise ValueError
                    name = bytes(raw[start:equals])
                    if not _ascii_identifier(name) or name in seen:
                        raise ValueError
                    seen.add(name)
                    if name == self._variable:
                        first, last = _dotenv_value_range(raw, equals + 1, end)
                        if last - first > 256:
                            raise ValueError
                        with memoryview(raw)[first:last] as view:
                            selected.extend(view)
                start = end + 1
            if not selected:
                raise ValueError
            return memoryview(selected)
        except Exception:
            _zeroize_mutable(selected)
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)


_REMOTE_USERNAME_TIMEOUT_SECONDS = 40
REMOTE_USERNAME_REFERENCE_CONTRACT = "fortipam-700-build29-linux-username-remote-reference-v1"
_REMOTE_REFERENCE_KEYS = frozenset({
    "contract", "ssh_host", "ssh_port", "ssh_username", "ssh_identity_file", "known_hosts_file", "known_hosts_digest",
    "bindings_path", "bindings_owner", "bindings_digest", "env_path", "env_owner", "username_variable",
})

# Fixed source-only operation. No configuration field can supply remote code.
_REMOTE_USERNAME_PROGRAM = r'''
import hashlib,json,os,re,stat,sys
from pathlib import Path

def erase(raw):
    raw[:]=b'\x00'*len(raw)

_BYTEARRAY_TYPE = bytearray

def _erase_transfer_storage(storage):
    try:
        erase(storage)
    except BaseException:
        for index in range(len(storage)):
            storage[index] = 0
        raise

def _take_mutable_prefix(storage, length):
    """Transfer an exact prefix, erasing the original allocation before release.

    Shrinking a populated bytearray may free an uncleared allocation. Copies
    here use a destination view, avoiding bytearray slice-assignment temporaries.
    The caller owns the returned array; failed transfers erase both allocations.
    """
    result = None
    try:
        try:
            if type(storage) is not _BYTEARRAY_TYPE or type(length) is not int or (not 0 <= length <= len(storage)):
                raise ValueError('The private mutable prefix is unavailable.')
            result = bytearray(length)
            with memoryview(storage) as source, memoryview(result) as destination:
                destination[:] = source[:length]
        finally:
            if type(storage) is _BYTEARRAY_TYPE:
                _erase_transfer_storage(storage)
    except BaseException:
        try:
            if result is not None:
                _erase_transfer_storage(result)
        finally:
            if type(storage) is _BYTEARRAY_TYPE:
                _erase_transfer_storage(storage)
        raise
    if result is None:
        raise ValueError('The private mutable prefix is unavailable.')
    return result

def read_fixed(path,owner,limit):
    raw=bytearray()
    try:
        raw=bytearray(limit+1); directory=None; descriptor=None
        try:
            path=Path(path)
            if not path.is_absolute() or '..' in path.parts: raise ValueError
            directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
            for part in path.parts[1:-1]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                os.close(directory);directory=child
            descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            before=os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or stat.S_IMODE(before.st_mode)!=0o600
                    or before.st_nlink!=1 or not 0<before.st_size<=limit): raise ValueError
            count=os.readv(descriptor,[raw]);after=os.fstat(descriptor)
            if (count!=before.st_size or os.read(descriptor,1) or
                    (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
                raise ValueError
            raw = _take_mutable_prefix(raw, count)
            return raw
        except BaseException:
            erase(raw);raise
        finally:
            if descriptor is not None: os.close(descriptor)
            if directory is not None: os.close(directory)
    except BaseException:
        _erase_transfer_storage(raw)
        raise

raw=bytearray();selected=bytearray()
try:
    p=json.load(sys.stdin)
    raw=read_fixed(p['bindings_path'],p['bindings_owner'],65536)
    if hashlib.sha256(raw).hexdigest()!=p['bindings_digest']: raise ValueError
    erase(raw)
    raw=read_fixed(p['env_path'],p['env_owner'],16384)
    if 0 in raw or 13 in raw: raise ValueError
    wanted=p['username_variable'].encode('ascii');seen=set();start=0
    while start<len(raw):
        end=raw.find(b'\n',start)
        if end<0: end=len(raw)
        if end!=start and raw[start]!=35:
            equals=raw.find(b'=',start,end)
            if equals<=start: raise ValueError
            name=bytes(raw[start:equals])
            if re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_]*',name) is None or name in seen: raise ValueError
            seen.add(name)
            if name==wanted:
                first,last=equals+1,end
                if first>=last: raise ValueError
                quote=raw[first]
                if quote in (34,39):
                    if last-first<3 or raw[last-1]!=quote: raise ValueError
                    first+=1;last-=1
                elif raw[last-1] in (34,39): raise ValueError
                if not 0<last-first<=256 or raw[first]==32 or raw[last-1] in (32,92): raise ValueError
                for index in range(first,last):
                    value=raw[index]
                    if value<32 or value==127 or (quote not in (34,39) and value==32): raise ValueError
                with memoryview(raw)[first:last] as view: selected.extend(view)
        start=end+1
    if not selected: raise ValueError
    erase(raw)
    sys.stdout.buffer.write(selected);sys.stdout.buffer.flush()
except BaseException:
    sys.exit(1)
finally:
    erase(raw);erase(selected)
'''


def _qualify_remote_identity_file(path: Path) -> None:
    """Check key metadata; literal spaces stay inside one shell-free SSH argument."""
    directory: int | None = None
    try:
        if (not path.is_absolute() or ".." in path.parts
                or any((char.isspace() and char != " ") or ord(char) < 32 or ord(char) == 127
                       or char in "\"'%" for char in str(path))):
            raise ValueError
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size <= 0):
            raise ValueError
    finally:
        if directory is not None:
            os.close(directory)


class OwnerOnlySecretApprovalBuild29RemoteUsernameSource:
    """Fixed SSH read of an original env, selected by protected metadata only.

    This source offers no caller-selectable host, command, shell, or variable.
    Construction is inert. Each read verifies the reference and original pin,
    and retains only a fresh mutable Username span in the private process.
    """

    def __init__(self, reference_path: Path) -> None:
        if not reference_path.is_absolute() or ".." in reference_path.parts:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE)
        self._path = reference_path

    def __repr__(self) -> str:
        return "<OwnerOnlySecretApprovalBuild29RemoteUsernameSource protected>"

    def _reference(self) -> dict[str, object]:
        raw, pin = bytearray(), bytearray()
        try:
            raw = _read_private_buffer(self._path, 16384)
            value = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if type(value) is not dict or set(value) != _REMOTE_REFERENCE_KEYS:
                raise ValueError
            if value["contract"] != REMOTE_USERNAME_REFERENCE_CONTRACT:
                raise ValueError
            if (type(value["ssh_host"]) is not str or not 0 < len(value["ssh_host"]) <= 253
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", value["ssh_host"]) is None
                    or type(value["ssh_username"]) is not str
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value["ssh_username"]) is None
                    or type(value["ssh_port"]) is not int or not 0 < value["ssh_port"] <= 65535):
                raise ValueError
            for name in ("bindings_owner", "env_owner"):
                if type(value[name]) is not int or not 0 <= value[name] <= 2**32 - 1:
                    raise ValueError
            for name in ("bindings_path", "env_path", "known_hosts_file", "ssh_identity_file"):
                if type(value[name]) is not str or not value[name] or any(ord(char) < 32 for char in value[name]):
                    raise ValueError
                path = Path(value[name])
                if not path.is_absolute() or ".." in path.parts:
                    raise ValueError
            if value["bindings_path"] == value["env_path"]:
                raise ValueError
            _qualify_remote_identity_file(Path(value["ssh_identity_file"]))
            _validated_variable_name(value["username_variable"])
            require_digest(value["bindings_digest"], "binding metadata")
            require_digest(value["known_hosts_digest"], "known host pin")
            pin = _read_private_buffer(Path(value["known_hosts_file"]), 16384, public_pin=True)
            if not hmac.compare_digest(hashlib.sha256(pin).hexdigest(), value["known_hosts_digest"]):
                raise ValueError
            return cast(dict[str, object], value)
        except Exception:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(pin)

    def read_span(self) -> memoryview:
        raw = bytearray()
        try:
            raw = bytearray(257)
            process: subprocess.Popen[bytes] | None = None
            succeeded = False
            try:
                reference = self._reference()
                argv = [
                    "/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                    "-o", "UserKnownHostsFile=" + cast(str, reference["known_hosts_file"]),
                    "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
                    "-o", "IdentitiesOnly=yes", "-i", cast(str, reference["ssh_identity_file"]),
                    "-p", str(reference["ssh_port"]), "-l", cast(str, reference["ssh_username"]),
                    cast(str, reference["ssh_host"]), shlex.join(["sudo", "-n", "python3", "-c", _REMOTE_USERNAME_PROGRAM]),
                ]
                payload = {name: reference[name] for name in (
                    "bindings_path", "bindings_owner", "bindings_digest", "env_path", "env_owner", "username_variable",
                )}
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
                if process.stdin is None or process.stdout is None:
                    raise ValueError
                encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                deadline, count, sent = time.monotonic() + _REMOTE_USERNAME_TIMEOUT_SECONDS, 0, 0
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                    selector.register(process.stdout, selectors.EVENT_READ)
                    finished = False
                    while not finished:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ValueError
                        ready = selector.select(remaining)
                        if not ready:
                            raise ValueError
                        for key, _ in ready:
                            if key.fileobj is process.stdin:
                                sent += os.write(process.stdin.fileno(), memoryview(encoded)[sent:])
                                if sent == len(encoded):
                                    selector.unregister(process.stdin)
                                    process.stdin.close()
                            else:
                                with memoryview(raw)[count:] as view:
                                    received = os.readv(process.stdout.fileno(), [view])
                                if not received:
                                    finished = True
                                    break
                                count += received
                                if count > 256:
                                    raise ValueError
                if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0 or not count:
                    raise ValueError
                raw = _take_mutable_prefix(raw, count)
                if any(value < 32 or value == 127 for value in raw):
                    raise ValueError
                result = memoryview(raw)
                succeeded = True
                return result
            except Exception:
                raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
            finally:
                try:
                    if process is not None:
                        if process.poll() is None:
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
                        process.wait(timeout=5)
                except Exception:
                    succeeded = False
                    raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
                finally:
                    if process is not None:
                        if process.stdin is not None:
                            process.stdin.close()
                        if process.stdout is not None:
                            process.stdout.close()
                    if not succeeded:
                        _zeroize_mutable(raw)
        except BaseException:
            _erase_transfer_storage(raw)
            raise



class OwnerOnlySecretApprovalBuild29QualificationVerifier:
    """Authenticate an independently issued exact-plan qualification receipt.

    The authority key is separate from the intent/approval signing authority.
    The issuer owns evidence truth and current permission qualification; this
    verifier establishes signature, fixed scope, binding, plan and freshness.
    There is deliberately no receipt issuance or boolean enabling fallback.
    """

    _contract = QUALIFICATION_CONTRACT
    _scope = QUALIFICATION_SCOPE
    _domain = _QUALIFICATION_DOMAIN

    def __init__(self, path: Path, *, authority_ref: str, authority_key: bytes,
                 expected_evidence_digest: str) -> None:
        try:
            require_ref(authority_ref, "qualification authority")
            require_digest(expected_evidence_digest, "qualification evidence")
            if (not path.is_absolute() or ".." in path.parts
                    or type(authority_key) is not bytes or len(authority_key) < 32):
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
        self._path = path
        self._authority = authority_ref
        self._key = authority_key
        self._evidence = expected_evidence_digest

    def __repr__(self) -> str:
        return "<OwnerOnlySecretApprovalBuild29QualificationVerifier protected>"

    def verify(self, *, binding_digest: str, plan_digest: str, now_epoch: int) -> None:
        raw = bytearray()
        try:
            require_digest(binding_digest, "binding digest")
            require_digest(plan_digest, "plan digest")
            if type(now_epoch) is not int or now_epoch < 0:
                raise ValueError
            raw = _read_private_buffer(self._path, 16384)
            document = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if type(document) is not dict or set(document) != {"body", "signature"}:
                raise ValueError
            body = document["body"]
            if type(body) is not dict or set(body) != {
                "contract", "authority_ref", "evidence_digest", "binding_digest", "plan_digest",
                "product_version", "product_build", "scope", "issued_at", "expires_at",
            }:
                raise ValueError
            pins = {"contract": self._contract, "authority_ref": self._authority,
                    "evidence_digest": self._evidence, "binding_digest": binding_digest,
                    "plan_digest": plan_digest, "product_version": "7.0.0", "product_build": 29,
                    "scope": self._scope}
            if any(type(body.get(name)) is not type(value) or body[name] != value
                   for name, value in pins.items()):
                raise ValueError
            issued, expires = body["issued_at"], body["expires_at"]
            if (type(issued) is not int or type(expires) is not int
                    or not 0 <= issued <= now_epoch < expires or not 0 < expires - issued <= 300):
                raise ValueError
            signature = document["signature"]
            require_digest(signature, "qualification signature")
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            expected = hmac.new(self._key, self._domain + canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)


class OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier(OwnerOnlySecretApprovalBuild29QualificationVerifier):
    """Independent Linux-only attestation; a signed Web receipt cannot qualify."""

    _contract = LINUX_QUALIFICATION_CONTRACT
    _scope = LINUX_QUALIFICATION_SCOPE
    _domain = _LINUX_QUALIFICATION_DOMAIN


def qualify_secret_approval_build29_linux_folder_acl(
    row: Mapping[str, object], *, folder_id: int, owner_name: str,
) -> str:
    """Bind the complete direct Linux Folder ACL and exact Owner relationship.

    This is a fixed disabled-inheritance scope. Groups and other users are
    permitted only as part of the independently pinned canonical ACL; they
    never establish the active Owner's permission by inference.
    """
    try:
        if (type(folder_id) is not int or not 0 < folder_id <= 2_147_483_647
                or type(owner_name) is not str or not owner_name
                or type(row.get("id")) is not int or row["id"] != folder_id
                or row.get("inherit-permission") != "disable"):
            raise ValueError
        projection: dict[str, object] = {
            "contract": "fortipam-700-build29-linux-folder-acl-v1",
            "id": folder_id, "inherit-permission": "disable", "owner_name": owner_name,
        }
        owner_count = 0
        for key, principal_key in (("user-permission", "user-name"), ("group-permission", "group-name")):
            normalized = _canonical_acl_projection(row.get(key), principal_key=principal_key)
            relations = _relations({key: normalized}, principal_key=principal_key)
            ids: set[int] = set()
            names: set[str] = set()
            semantics: list[tuple[int, tuple[str, ...], str, str]] = []
            for relation in relations:
                if (relation.relation_id <= 0 or relation.relation_id in ids
                        or names.intersection(relation.names)
                        or relation.folder_permission not in _FOLDER_PERMISSIONS
                        or relation.secret_permission not in _SECRET_PERMISSIONS):
                    raise ValueError
                ids.add(relation.relation_id)
                names.update(relation.names)
                if principal_key == "user-name" and owner_name in relation.names:
                    if (relation.names != (owner_name,) or relation.folder_permission != "owner"
                            or relation.secret_permission != "owner"):
                        raise ValueError
                    owner_count += 1
                semantics.append((relation.relation_id, tuple(sorted(relation.names)),
                                  relation.folder_permission, relation.secret_permission))
            projection[key] = sorted(semantics)
        if owner_count != 1:
            raise ValueError
        return canonical_digest(projection)
    except Exception:
        raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None


class SecretApprovalBuild29RuntimeProducer:
    """Compile one real private transition after complete signed intent validation."""

    def __init__(self, owner: OwnerSessionMetadataTransport, sources: SecretApprovalBuild29PrivateSources,
                 *, binding: ApprovalAndObserveBinding, expected_folder_id: int, expected_serial: str,
                 web_url: str | None = None,
                 username_source: OwnerOnlySecretApprovalBuild29UsernameSource | OwnerOnlySecretApprovalBuild29EnvUsernameSource | OwnerOnlySecretApprovalBuild29RemoteUsernameSource,
                 claim_directory: Path, execution_enabled: bool = False,
                 linux_target_name: str | None = None, linux_target_ipv4_address: str | None = None,
                 expected_folder_acl_digest: str | None = None) -> None:
        try:
            from .secret_approval_build29_private_sources import SecretApprovalBuild29PrivateSources
            if (type(binding) is not ApprovalAndObserveBinding
                    or not isinstance(owner, OwnerSessionMetadataTransport) or owner._client is not None
                    or type(sources) is not SecretApprovalBuild29PrivateSources
                    or type(username_source) not in {OwnerOnlySecretApprovalBuild29UsernameSource, OwnerOnlySecretApprovalBuild29EnvUsernameSource, OwnerOnlySecretApprovalBuild29RemoteUsernameSource}
                    or type(execution_enabled) is not bool):
                raise ValueError
            _assert_bound_sources(owner, sources, binding, expected_folder_id, expected_serial)
            if sources._linux_target_name != linux_target_name:
                raise ValueError
            if linux_target_name is None:
                if expected_folder_acl_digest is not None or linux_target_ipv4_address is not None or type(username_source) is not OwnerOnlySecretApprovalBuild29UsernameSource:
                    raise ValueError
                if web_url is None:
                    raise ValueError
                SecretApprovalBuild29WebFieldsBinding(web_url, username_source.read_span)
            else:
                if web_url is not None or linux_target_ipv4_address is None or expected_folder_acl_digest is None:
                    raise ValueError
                require_digest(expected_folder_acl_digest, "Linux Folder ACL")
                SecretApprovalBuild29LinuxFieldsBinding(linux_target_name, linux_target_ipv4_address, username_source.read_span)
            # Validate transport selectors now, without any private source production.
            FortiPamSecretApprovalBuild29HttpTransport(
                owner, expected_secret_id=binding.secret_id, expected_secret_name=binding.secret_name,
                expected_folder_id=expected_folder_id, folder_path=binding.folder_path,
                expected_serial=expected_serial, linux_target_name=linux_target_name,
            )
        except Exception:
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
        self._owner, self._sources, self._binding = owner, sources, binding
        self._folder_id, self._serial = expected_folder_id, expected_serial
        self._web_url, self._username = web_url, username_source
        self._linux_target_name, self._linux_target_ipv4_address = linux_target_name, linux_target_ipv4_address
        self._folder_acl_digest = expected_folder_acl_digest
        self._claims, self._enabled = claim_directory, execution_enabled
        self._lock = Lock()
        self._produced = False

    def __repr__(self) -> str:
        return "<SecretApprovalBuild29RuntimeProducer protected>"

    def produce(self, approval_binding: ApprovalAndObserveBinding) -> SecretApprovalBuild29PrivateTransition:
        if not self._lock.acquire(blocking=False):
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE)
        transport: FortiPamSecretApprovalBuild29HttpTransport | None = None
        try:
            if self._enabled is not True or self._produced or approval_binding != self._binding:
                raise ValueError
            self._assert_sources()
            self._produced = True
            owner, binding = self._owner, self._binding
            with owner.authenticated():
                self._qualify_owner_access()
                schema = self._sources.approval_schema()
            if owner.logout_verified is not True:
                raise ValueError
            profile = SecretApprovalBuild29ProfileReader(
                owner, expected_serial=self._serial, profile_name=binding.approval_profile_name,
            )
            folder_acl_digest = self._folder_acl_digest
            mutation = SecretApprovalBuild29MutationBinding(
                schema=schema, approval_profile_name=binding.approval_profile_name,
                profile_digest=profile.current_configuration_digest,
                native_preservation_digest=lambda values: self._native_digest(
                    values, expected_folder_acl_digest=folder_acl_digest,
                ),
                claim_directory=self._claims, expected_folder_acl_digest=self._folder_acl_digest,
                ack_verifier=lambda status, raw: qualify_secret_approval_build29_put_ack(
                    status, raw, expected_serial=self._serial, expected_secret_id=binding.secret_id,
                ),
                web_fields=(SecretApprovalBuild29WebFieldsBinding(self._web_url, self._username.read_span)
                            if self._web_url is not None else None),
                linux_fields=(SecretApprovalBuild29LinuxFieldsBinding(
                    self._linux_target_name, self._linux_target_ipv4_address, self._username.read_span,
                ) if self._linux_target_name is not None and self._linux_target_ipv4_address is not None else None),
            )
            transport = FortiPamSecretApprovalBuild29HttpTransport(
                owner, expected_secret_id=binding.secret_id, expected_secret_name=binding.secret_name,
                expected_folder_id=self._folder_id, folder_path=binding.folder_path,
                expected_serial=self._serial, mutation=mutation, execution_enabled=True,
                linux_target_name=self._linux_target_name,
            )
            baseline = transport.inspect_transition()
            if baseline.approval_values != ("disable", "disable", "disable", ""):
                raise ValueError
            expected = transport._transition_state(
                ("enable", "disable", "disable", binding.approval_profile_name),
                baseline.metadata_digest, baseline.profile_digest, baseline.native_digest,
            )
            return SecretApprovalBuild29PrivateTransition(
                transport, baseline, expected,
                secret_approval_build29_transport_binding_digest(transport, binding.secret_approval_object_ref),
            )
        except Exception:
            if transport is not None:
                transport.close()
            raise SecretApprovalBuild29RuntimeProviderError(_UNAVAILABLE) from None
        finally:
            self._lock.release()

    def _assert_sources(self) -> None:
        _assert_bound_sources(self._owner, self._sources, self._binding, self._folder_id, self._serial)
        if self._sources._linux_target_name != self._linux_target_name:
            raise ValueError

    def _native_digest(self, approval_values: tuple[str, str, str, str], *,
                       expected_folder_acl_digest: str | None = None) -> str:
        if (expected_folder_acl_digest is not None
                and self._folder_acl_digest != expected_folder_acl_digest):
            raise ValueError
        self._assert_sources()
        self._qualify_owner_access()
        return self._sources.native_preservation_digest(approval_values)

    def _qualify_owner_access(self) -> None:
        owner, binding = self._owner, self._binding
        if (owner._client is None or owner._clock() >= owner._expires_at
                or owner.resolve_folder_id(binding.folder_path) != self._folder_id
                or owner._lookup_id("secret", binding.folder_path + "/" + binding.secret_name) != binding.secret_id
                or owner._clock() >= owner._expires_at):
            raise ValueError
        if self._linux_target_name is None:
            if owner._verify_collector_folder_acl(self._folder_id, owner._owner_name) is not True:
                raise ValueError
        else:
            status, payload = owner._request(
                "GET", f"/api/v2/cmdb/secret/folder/{self._folder_id}", None,
                query="format=id%7Cinherit-permission%7Cuser-permission%7Cgroup-permission",
            )
            row = _record(payload)
            if status != 200 or row is None or self._folder_acl_digest is None:
                raise ValueError
            current = qualify_secret_approval_build29_linux_folder_acl(
                row, folder_id=self._folder_id, owner_name=owner._owner_name,
            )
            if not hmac.compare_digest(current, self._folder_acl_digest):
                raise ValueError
        if owner._clock() >= owner._expires_at:
            raise ValueError


def _assert_bound_sources(owner: OwnerSessionMetadataTransport, sources: SecretApprovalBuild29PrivateSources,
                          binding: ApprovalAndObserveBinding, folder_id: int, serial: str) -> None:
    if (sources._owner is not owner or sources._serial != serial
            or sources._identity != {"id": binding.secret_id, "name": binding.secret_name, "folder": folder_id}
            or sources._folder != binding.folder_path
            or sources._path != "/api/v2/cmdb/secret/database/" + str(binding.secret_id)):
        raise ValueError
    sources._check_binding()


__all__ = [
    "OwnerOnlySecretApprovalBuild29QualificationVerifier", "OwnerOnlySecretApprovalBuild29UsernameSource",
    "OwnerOnlySecretApprovalBuild29RemoteUsernameSource",
    "OwnerOnlySecretApprovalBuild29EnvUsernameSource", "OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier",
    "qualify_secret_approval_build29_linux_folder_acl",
    "SecretApprovalBuild29RuntimeProducer", "SecretApprovalBuild29RuntimeProviderError",
]
