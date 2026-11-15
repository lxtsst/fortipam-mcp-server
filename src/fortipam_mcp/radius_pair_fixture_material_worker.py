"""Fixed standalone paired RADIUS fixture worker; uninstalled and inactive.

Standalone standard-library program for a separately qualified dedicated SSH
identity. The production entry point accepts no arguments, paths or commands.
It does not install itself, enable SSH access or modify the running fixture.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable

CONTRACT = "radius-owned-pair-fixture-material-channel-v1"
_ROOT = Path("/var/lib/fortipam-mcp/radius-pair-fixture")
_REQUEST_FIELDS = {"action_id", "action_version", "plan_digest", "policy_decision_digest",
    "authorization_digest", "scope_digest", "audience_digest", "provider_class", "purpose",
    "requested_at", "expires_at"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _wipe(value: bytearray) -> None:
    value[:] = bytes(len(value))
    try: value.clear()
    except BufferError: pass


_BYTEARRAY_TYPE = bytearray


def _erase_transfer_storage(storage: bytearray) -> None:
    try:
        _wipe(storage)
    except BaseException:
        for index in range(len(storage)):
            storage[index] = 0
        raise


def _take_mutable_prefix(storage: bytearray, length: int) -> bytearray:
    """Transfer an exact prefix, erasing the original allocation before release.

    Shrinking a populated bytearray may free an uncleared allocation. Copies
    here use a destination view, avoiding bytearray slice-assignment temporaries.
    The caller owns the returned array; failed transfers erase both allocations.
    """
    result: bytearray | None = None
    try:
        try:
            if (type(storage) is not _BYTEARRAY_TYPE or type(length) is not int
                    or not 0 <= length <= len(storage)):
                raise ValueError("The private mutable prefix is unavailable.")
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
        raise ValueError("The private mutable prefix is unavailable.")
    return result


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result: raise ValueError
        result[key] = value
    return result


def _json(value: bytearray) -> dict[str, Any]:
    decoded = json.loads(value, object_pairs_hook=_pairs)
    if type(decoded) is not dict: raise ValueError
    return decoded


def _directory(path: Path, uid: int) -> int:
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        if not path.is_absolute() or ".." in path.parts: raise ValueError
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read(directory: int, name: str, uid: int, maximum: int) -> bytearray:
    raw = bytearray()
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        raw = bytearray(maximum + 1)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= maximum): raise ValueError
            count = 0
            while count < before.st_size:
                with memoryview(raw)[count:before.st_size] as view:
                    received = os.readv(descriptor,[view])
                if received <= 0: raise ValueError
                count += received
            after = os.fstat(descriptor)
            if (os.read(descriptor,1) or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                    != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)): raise ValueError
            raw = _take_mutable_prefix(raw, count)
            return raw
        except BaseException:
            _wipe(raw)
            raise
        finally:
            os.close(descriptor)
    except BaseException:
        _erase_transfer_storage(raw)
        raise


def _metadata(directory: int, name: str, uid: int) -> dict[str, Any]:
    raw = _read(directory,name,uid,16384)
    try: return _json(raw)
    finally: _wipe(raw)


def _exists(directory: int, name: str) -> bool:
    try: os.stat(name,dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError: return False
    return True


def _claim(directory: int, value: dict[str, Any]) -> None:
    data = json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    descriptor = os.open("create-material.claim.json", os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                         0o600,dir_fd=directory)
    try:
        offset = 0
        while offset < len(data):
            sent = os.write(descriptor,data[offset:])
            if sent <= 0: raise ValueError
            offset += sent
        os.fsync(descriptor)
        os.fsync(directory)
    finally: os.close(descriptor)


def _clock(request: dict[str, Any], policy: dict[str, Any], now: int) -> None:
    if (type(now) is not int or type(request["requested_at"]) is not int
            or type(request["expires_at"]) is not int or type(policy["expires_at"]) is not int
            or not 0 <= request["requested_at"] <= now < request["expires_at"]
            or not 0 < request["expires_at"]-request["requested_at"] <= 60
            or request["expires_at"] > policy["expires_at"]): raise ValueError


def _inspect(container_id: str) -> dict[str, Any]:
    result = subprocess.run(["/usr/bin/docker","container","inspect",container_id],
        capture_output=True,check=True,timeout=5)
    values = json.loads(result.stdout)
    if type(values) is not list or len(values) != 1 or type(values[0]) is not dict: raise ValueError
    return values[0]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def _address(value: object) -> str:
    if type(value) is not str: raise ValueError
    address = ipaddress.IPv4Address(value)
    if (str(address) != value or not address.is_private or address.is_loopback
            or address.is_unspecified or address.is_link_local or address.is_multicast): raise ValueError
    return value


def _fixture(root: Path, expected: object, server: str, *, inspector: Callable[[str],dict[str,Any]],
             owner_uid: int, config_uid: int, expires_at: int) -> dict[str,Any]:
    """Qualified metadata only; never read shared material or client blocks."""
    if type(expected) is not dict or set(expected) != {"binding","ack","config_digest"}: raise ValueError
    directory = config = material_dir = None
    main = bytearray()
    try:
        directory = _directory(root,owner_uid)
        bound = _metadata(directory,"binding.private.json",owner_uid)
        ack = _metadata(directory,"start.ack.json",owner_uid)
        if (bound != expected["binding"] or ack != expected["ack"]
                or ack["nonce"] != bound["fixture_nonce"] or _address(bound["server_ip"]) != server
                or type(bound["expires_at"]) is not int or expires_at > bound["expires_at"]
                or type(ack["container_id"]) is not str or _HEX.fullmatch(ack["container_id"]) is None
                or type(expected["config_digest"]) is not str or _HEX.fullmatch(expected["config_digest"]) is None): raise ValueError
        _address(bound["device_ip"])
        config = _directory(root/"config",config_uid)
        main = _read(config,"radiusd.conf",config_uid,32768)
        if hashlib.sha256(main).hexdigest() != expected["config_digest"]: raise ValueError
        current = inspector(ack["container_id"])
        if (current["Id"] != ack["container_id"] or current["State"]["Running"] is not True
                or current["Image"] != bound["image_id"]
                or current["Config"]["Labels"]["fortipam.radius.fixture"] != bound["fixture_nonce"]
                or current["Config"]["User"] != "10001:10001"
                or current["HostConfig"]["ReadonlyRootfs"] is not True
                or current["HostConfig"]["LogConfig"]["Type"] != "none"
                or not any(m["Source"] == str(root/"config") and m["Destination"] == "/radius-config"
                    and m["Type"] == "bind" and m["RW"] is False for m in current["Mounts"])): raise ValueError
        material_dir = _directory(root/"material",owner_uid)
        info = os.stat("primary-secret",dir_fd=material_dir,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 32): raise ValueError
        return bound
    finally:
        _wipe(main)
        for fd in (material_dir,config,directory):
            if fd is not None: os.close(fd)


def _ready(directory: int, value: dict[str,Any]) -> None:
    """Internal marker of validated bytes, not proof of client receipt."""
    raw = json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    fd = os.open("material-ready.ack.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd,raw[offset:])
            if written <= 0: raise ValueError
            offset += written
        os.fsync(fd);os.fsync(directory)
    finally: os.close(fd)


def _handle(root: Path, incoming: dict[str,Any], *, clock: Callable[[],int],
            inspector: Callable[[str],dict[str,Any]], owner_uid: int = 0, config_uid: int = 10001) -> bytearray:
    """Test seam only; main fixes root and both child paths and accepts no args."""
    directory = selected = primary = secondary = config = material_dir = None
    material,clients,wanted = bytearray(),bytearray(),bytearray()
    try:
        if (type(incoming) is not dict
                or set(incoming) != {"contract","operation","ordinal","parameters_digest","source_policy_digest","request"}
                or incoming["contract"] != CONTRACT): raise ValueError
        operation,ordinal = incoming["operation"],incoming["ordinal"]
        if not (operation == "validate" and ordinal == "both"
                or operation == "acquire" and ordinal in {"primary","secondary"}): raise ValueError
        request = incoming["request"]
        if type(request) is not dict or set(request) != _REQUEST_FIELDS: raise ValueError
        if (request["action_id"] != "radius-server-pair-create" or request["action_version"] != "1.0.0"
                or request["provider_class"] != "owned_lab_fixture_reference"
                or request["purpose"] != "initial_onboarding"): raise ValueError
        for key in ("plan_digest","policy_decision_digest","authorization_digest","scope_digest","audience_digest"):
            if type(request[key]) is not str or _HEX.fullmatch(request[key]) is None: raise ValueError
        directory = _directory(root,owner_uid)
        policy = _metadata(directory,"pair-material-policy.json",owner_uid)
        if (_digest(policy) != incoming["source_policy_digest"]
                or set(policy) != {"contract","parameters_digest","scope_digest","audience_digest","binding","fixtures","expires_at"}
                or policy["contract"] != CONTRACT
                or policy["parameters_digest"] != incoming["parameters_digest"]
                or policy["scope_digest"] != request["scope_digest"]
                or policy["audience_digest"] != request["audience_digest"]): raise ValueError
        b = policy["binding"]
        if (type(b) is not dict or set(b) != {"name","server","secondary_server","private_nonce"}
                or type(b["name"]) is not str or re.fullmatch(r"mcp-v4-radius-[a-z0-9][a-z0-9-]{0,20}",b["name"]) is None
                or type(b["private_nonce"]) is not str or _HEX.fullmatch(b["private_nonce"]) is None
                or _address(b["server"]) == _address(b["secondary_server"])): raise ValueError
        parameters = {"contract":"fortipam-700-build29-radius-pair-create-private-v1",
            "intent":{"name":b["name"],"auth-type":"auto","server":b["server"],"secondary-server":b["secondary_server"]},
            "private_nonce":b["private_nonce"]}
        if _digest(parameters) != policy["parameters_digest"]: raise ValueError
        fixtures = policy["fixtures"]
        if type(fixtures) is not dict or set(fixtures) != {"primary","secondary"}: raise ValueError
        first = clock();_clock(request,policy,first)
        primary = _directory(root/"primary",owner_uid)
        secondary = _directory(root/"secondary",owner_uid)
        bound_primary = _fixture(root/"primary",fixtures["primary"],b["server"],inspector=inspector,
            owner_uid=owner_uid,config_uid=config_uid,expires_at=policy["expires_at"])
        bound_secondary = _fixture(root/"secondary",fixtures["secondary"],b["secondary_server"],inspector=inspector,
            owner_uid=owner_uid,config_uid=config_uid,expires_at=policy["expires_at"])
        if (bound_primary["device_ip"] != bound_secondary["device_ip"]
                or fixtures["primary"]["ack"]["container_id"] == fixtures["secondary"]["ack"]["container_id"]
                or bound_primary["fixture_nonce"] == bound_secondary["fixture_nonce"]): raise ValueError
        context = {"contract":CONTRACT,"parameters_digest":policy["parameters_digest"],
            "source_policy_digest":incoming["source_policy_digest"],"request_digest":_digest(request)}
        if ordinal in {"both","primary"}:
            if any(_exists(fd,"create-material.claim.json") or _exists(fd,"material-ready.ack.json")
                    for fd in (directory,primary,secondary)): raise ValueError
        else:
            group = _metadata(directory,"create-material.claim.json",owner_uid)
            primary_claim = _metadata(primary,"create-material.claim.json",owner_uid)
            if (set(group) != {*context,"claimed_at"} or any(group[k] != v for k,v in context.items())
                    or type(group["claimed_at"]) is not int or not request["requested_at"] <= group["claimed_at"] <= first
                    or primary_claim != group | {"ordinal":"primary"}
                    or _metadata(primary,"material-ready.ack.json",owner_uid) != {
                        "contract":CONTRACT,"claim_digest":_digest(primary_claim)}
                    or _exists(secondary,"create-material.claim.json")
                    or _exists(secondary,"material-ready.ack.json")): raise ValueError
        now = clock();_clock(request,policy,now)
        if now < first or _metadata(directory,"pair-material-policy.json",owner_uid) != policy: raise ValueError
        if operation == "validate": return bytearray(b"available\n")
        selected = primary if ordinal == "primary" else secondary
        selected_root = root/"primary" if ordinal == "primary" else root/"secondary"
        if ordinal == "primary":
            group = context | {"claimed_at":now}
            _claim(directory,group)
        _claim(selected,group | {"ordinal":ordinal})
        material_dir = _directory(selected_root/"material",owner_uid)
        config = _directory(selected_root/"config",config_uid)
        material = _read(material_dir,"primary-secret",owner_uid,32)
        if len(material) != 32 or any(x not in _ALPHABET for x in material): raise ValueError
        clients = _read(config,"clients.conf",config_uid,4096)
        bound = bound_primary if ordinal == "primary" else bound_secondary
        for index,address in enumerate((bound["device_ip"],bound["server_ip"])):
            wanted.extend(("client fixture_"+str(index)+" {\n ipaddr = "+address+
                "/32\n proto = udp\n require_message_authenticator = yes\n limit_proxy_state = yes\n secret = \"").encode())
            wanted.extend(material);wanted.extend(b'"\n}\n')
        if clients != wanted: raise ValueError
        final = clock();_clock(request,policy,final)
        if final < now or _metadata(directory,"pair-material-policy.json",owner_uid) != policy: raise ValueError
        # Repeat both ownership/config checks after reading, before releasing bytes.
        if (_fixture(root/"primary",fixtures["primary"],b["server"],inspector=inspector,
                owner_uid=owner_uid,config_uid=config_uid,expires_at=policy["expires_at"]) != bound_primary
                or _fixture(root/"secondary",fixtures["secondary"],b["secondary_server"],inspector=inspector,
                    owner_uid=owner_uid,config_uid=config_uid,expires_at=policy["expires_at"]) != bound_secondary): raise ValueError
        after = clock();_clock(request,policy,after)
        if after < final: raise ValueError
        _ready(selected,{"contract":CONTRACT,"claim_digest":_digest(group | {"ordinal":ordinal})})
        result,material = material,bytearray()
        return result
    finally:
        for value in (material,clients,wanted): _wipe(value)
        for fd in (material_dir,config,primary,secondary,directory):
            if fd is not None: os.close(fd)


def main() -> int:
    request,output = bytearray(),bytearray()
    try:
        if len(sys.argv) != 1 or os.geteuid() != 0 or os.environ.get("SSH_ORIGINAL_COMMAND"): raise ValueError
        def expired(signum: int, frame: object) -> None: raise TimeoutError
        signal.signal(signal.SIGALRM,expired);signal.alarm(20)
        request.extend(sys.stdin.buffer.read(16385))
        if not 0 < len(request) <= 16384: raise ValueError
        output = _handle(_ROOT,_json(request),clock=lambda:int(time.time()),inspector=_inspect)
        offset = 0
        while offset < len(output):
            with memoryview(output)[offset:] as view: written = os.write(sys.stdout.fileno(),view)
            if written <= 0: raise OSError
            offset += written
        return 0
    except BaseException:
        return 1
    finally:
        signal.alarm(0)
        _wipe(request);_wipe(output)


if __name__ == "__main__":
    raise SystemExit(main())
