"""Write-once protected original inputs for independent readonly EMS recovery.

The packet precedes the first M4 claim. It is not ownership: reopening also
requires the original checkpointed verified M4 and complete birth custody.
No product response, cookie, source key or signing key is serialized.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import os
from pathlib import Path
import stat
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan

from .ems_tag_contract import DisabledLinuxProcessTag, _canonical
from .ems_tag_custody import EmsTagOriginalActorBinding, EmsTagOriginalCustody, _decode
from .ems_tag_fpa_sources import EmsTagFpaBinding
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import MonotonicM4ExecutionCheckpoint, PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_DOMAIN = b"ems-tag-original-recovery-input/v1\x00"
_DOMAIN_V2 = b"ems-tag-original-recovery-input/v2\x00"
_ERROR = "The private original EMS binding is unavailable."


def retain_original_binding(path: Path, custody: EmsTagOriginalCustody, *,
                            fpa_binding: EmsTagFpaBinding | None = None) -> None:
    """Persist exact original inputs before dispatch; never overwrite a packet."""
    raw = bytearray()
    try:
        if type(custody) is not EmsTagOriginalCustody or custody._store._read_only:
            raise ValueError
        custody._validate()
        if custody._store.claim_count != 0 or any(custody._directory.iterdir()):
            raise ValueError
        path = Path(path)
        _private_directory(path.parent)
        parent_info = path.parent.stat()
        value = {"contract": "ems-tag-original-recovery-input-v1", "path": str(path.absolute()),
            "parent_identity": [parent_info.st_dev, parent_info.st_ino],
            "custody_context": custody._context, "context_fields": custody._context_fields(),
            "draft_nonce": custody._draft.nonce, "actor": asdict(custody._actor_binding),
            "plan": asdict(custody._plan), "authorization": asdict(custody._authorization),
            "checkpoint_store_ref": custody._store._checkpoint_store_ref}
        domain = _DOMAIN
        if fpa_binding is not None:
            if type(fpa_binding) is not EmsTagFpaBinding:
                raise ValueError
            fpa_binding.__post_init__()
            value.update(contract="ems-tag-original-recovery-input-v2", fpa_binding=asdict(fpa_binding))
            domain = _DOMAIN_V2
        signature = hmac.new(custody._key, domain + _canonical(value), hashlib.sha256).hexdigest()
        raw.extend(_canonical({"value": value, "signature": signature}))
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                raise ValueError
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)
        check = _read(path, 32768)
        try:
            if not hmac.compare_digest(check, raw):
                raise ValueError
        finally:
            _zeroize_mutable(check)
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)


def _verified_packet(path: Path, witness_key_file: Path) -> dict[str, Any]:
    raw = bytearray()
    try:
        path = Path(path)
        _private_directory(path.parent)
        raw = _read(path, 32768)
        packet = _decode(raw)
        if type(packet) is not dict or set(packet) != {"value", "signature"}:
            raise ValueError
        value = packet["value"]
        base_fields = {"contract", "path", "parent_identity",
                "custody_context", "context_fields", "draft_nonce", "actor", "plan",
                "authorization", "checkpoint_store_ref"}
        if type(value) is not dict:
            raise ValueError
        version2 = value.get("contract") == "ems-tag-original-recovery-input-v2"
        if (set(value) != base_fields | ({"fpa_binding"} if version2 else set())
                or value["contract"] not in ("ems-tag-original-recovery-input-v1", "ems-tag-original-recovery-input-v2")
                or value["path"] != str(path.absolute())
                or type(packet["signature"]) is not str):
            raise ValueError
        key = _key(witness_key_file)
        expected = hmac.new(key, (_DOMAIN_V2 if version2 else _DOMAIN) + _canonical(value), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, packet["signature"]):
            raise ValueError
        info = path.parent.stat()
        if value["parent_identity"] != [info.st_dev, info.st_ino]:
            raise ValueError
        if version2:
            EmsTagFpaBinding(**value["fpa_binding"]).__post_init__()
        return value
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)


def load_original_binding(path: Path, witness_key_file: Path, *,
        monotonic_checkpoint: MonotonicM4ExecutionCheckpoint,
        checkpoint_store_ref: str) -> EmsTagOriginalCustody:
    """Reconstruct only the original readonly evidence, never a new create."""
    try:
        value = _verified_packet(path, witness_key_file)
        if value["checkpoint_store_ref"] != checkpoint_store_ref:
            raise ValueError
        fields = value["context_fields"]
        if type(fields) is not dict or fields.get("witness_key_path") != str(witness_key_file.absolute()):
            raise ValueError
        store = PersistentM4ExecutionStateStore(Path(fields["store_path"]), Path(fields["store_key_path"]),
            read_only=True, monotonic_checkpoint=monotonic_checkpoint, checkpoint_store_ref=checkpoint_store_ref)
        custody = EmsTagOriginalCustody(Path(fields["directory"]), witness_key_file,
            DisabledLinuxProcessTag(value["draft_nonce"]), fields["baseline"],
            M4ExecutionPlan(**value["plan"]), M4ExecutionAuthorization(**value["authorization"]), store,
            source_context_digest=fields["source"], actor_binding=EmsTagOriginalActorBinding(**value["actor"]))
        if (custody._context != value["custody_context"]
                or _canonical(custody._context_fields()) != _canonical(fields)):
            raise ValueError
        custody.inspect_created_scope()
        return custody
    except Exception:
        raise ValueError(_ERROR) from None


def load_original_fpa_binding(path: Path, witness_key_file: Path, *,
                              original: EmsTagOriginalCustody) -> EmsTagFpaBinding:
    """Only the verified original's signed v2 packet supplies its FPA scope."""
    try:
        if type(original) is not EmsTagOriginalCustody or original._store._read_only is not True:
            raise ValueError
        original.inspect_created_scope()
        value = _verified_packet(path, witness_key_file)
        if (value["contract"] != "ems-tag-original-recovery-input-v2"
                or value["custody_context"] != original._context
                or Path(witness_key_file) != original._key_file
                or _canonical(value["context_fields"]) != _canonical(original._context_fields())):
            raise ValueError
        return EmsTagFpaBinding(**value["fpa_binding"])
    except Exception:
        raise ValueError(_ERROR) from None
