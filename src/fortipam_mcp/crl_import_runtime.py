"""Owner-only default-closed native CRL startup; no device I/O at construction."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path

from .crl_import_mcp_action import NativeCrlMcpAction
from .crl_import_transport import NativeCrlTransport
from .crl_import_workflow import NativeCrlWorkflow
from .ldap_server_runtime import _decode, _key, _path, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_CRL_700_"
CONTRACT = "fortipam-native-crl-startup-v1"
_ERROR = "FortiPAM CRL startup is unavailable."


def _flag(environment: Mapping[str, str], name: str) -> bool:
    raw = environment.get(PREFIX + name, "false")
    if type(raw) is not str or raw not in {"true", "false"}:
        raise ValueError(_ERROR)
    return raw == "true"


def build_crl_candidate(environment: Mapping[str, str]) -> NativeCrlMcpAction | None:
    try:
        enabled = _flag(environment, "ENABLED")
        create, recover = _flag(environment, "IMPORT_ENABLED"), _flag(environment, "RECOVERY_ENABLED")
        if not enabled:
            if create or recover:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        raw = _read(manifest_path, 16384)
        try:
            manifest = _decode(bytes(raw))
        finally:
            raw[:] = bytes(len(raw))
        if (set(manifest) != {"contract", "binding", "identity"} or manifest["contract"] != CONTRACT
                or set(manifest["binding"]) != {"nonce", "serial", "owner_name"}
                or set(manifest["identity"]) != {"environment_ref", "scope_ref", "audience_ref",
                    "allowed_requester_digest", "allowed_transport_digest"}):
            raise ValueError
        directory = manifest_path.parent
        _private_directory(directory)
        files = {name: directory / name for name in ("issuer.pem", "crl.pem", "authority.key", "execution.key")}
        issuer = _read(files["issuer.pem"], 16384)
        crl = _read(files["crl.pem"], 262144)
        try:
            authority, execution = _key(files["authority.key"]), _key(files["execution.key"])
            if hmac.compare_digest(authority, execution):
                raise ValueError
            config = load_secret_metadata_http_transport_config(environment)
            credentials = owner_login_provider(environment)
            if credentials is None:
                raise ValueError
            binding = manifest["binding"]
            def factory() -> OwnerSessionMetadataTransport:
                return OwnerSessionMetadataTransport(config, owner_name=binding["owner_name"], credentials=credentials,
                    folder_path="native-crl-laboratory", secret_name="native-crl-laboratory",
                    target_name="native-crl-laboratory", witness=FortiPamSecretMetadataHttpTransport(config))
            transport = NativeCrlTransport(owner_factory=factory, crl_pem=bytes(crl), issuer_pem=bytes(issuer), **binding)
        finally:
            issuer[:] = bytes(len(issuer))
            crl[:] = bytes(len(crl))
        database, marker = directory / "execution.sqlite3", directory / "crl.namespace"
        namespace = {"manifest": manifest, "origin": config.base_url, "ca": config.ca_file,
            "parameters": transport.parameters_digest, "authority": hashlib.sha256(authority).hexdigest(),
            "execution": hashlib.sha256(execution).hexdigest(), "directory": str(directory),
            "directory_identity": (directory.stat().st_dev, directory.stat().st_ino)}
        pin = hmac.new(execution, b"fortipam-native-crl-startup-v1\0" + json.dumps(namespace,
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest().encode()
        family = [Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")]
        if os.path.lexists(marker):
            previous = _read(marker, 128)
            try:
                if not database.is_file() or not hmac.compare_digest(bytes(previous), pin):
                    raise ValueError
            finally:
                previous[:] = bytes(len(previous))
        else:
            if any(os.path.lexists(path) for path in family):
                raise ValueError
            descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(pin)
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        store = PersistentM4ExecutionStateStore(database, files["execution.key"])
        workflow = NativeCrlWorkflow(transport, store, authority_key=authority,
            import_enabled=create, recovery_enabled=recover, **manifest["identity"])
        return NativeCrlMcpAction(workflow)
    except Exception:
        raise ValueError(_ERROR) from None
