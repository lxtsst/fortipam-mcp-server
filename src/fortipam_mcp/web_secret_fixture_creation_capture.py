"""Private opt-in factory capture of an original Web creation, no cleanup rights."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import threading
from typing import cast
from urllib.parse import urlsplit

from v4_planning import canonical_digest
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import FortiPam191SecretCreatePrivateAdapter, SecretCreate191WebBinding
from .secret_create_central_lab_provider import CentralLabSecretCreate191LeaseTransport
from .secret_create_191_projection_reader import SecretCreate191ProjectionReader
from .secret_create_m4_runtime import ProtectedSecretCreateM4Runtime, SecretCreateM4ExecutionBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .secret_onboarding_action_sequence import _SecretCreateRunner
from .secret_onboarding_projection_source import WebSecretOnboardingBinding
from .web_secret_fixture_creation import WebSecretFixtureCreationEvidence
from .web_secret_fixture_creation_record import WebSecretFixtureCreationRecord
from .web_secret_fixture_creation_record import WebSecretFixtureAcknowledgedCreation
from .web_secret_create_ack import WebSecretCreateAckCapture

_ERROR = "The private Web fixture factory capture is unavailable."
_ATTEMPT = "creation.attempt"


class WebSecretFixtureCaptureError(ValueError):
    """Categorical refusal; an original consumed execution is never retried."""


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureCaptureSettings:
    """Explicit private startup inputs; no environment or default activation."""

    serial_digest: str
    expected_store_digest: str
    directory: Path
    key_file: Path
    ack_capture: WebSecretCreateAckCapture | None = None

    def __repr__(self) -> str:
        return "<WebSecretFixtureCaptureSettings redacted>"

    __str__ = __repr__

    def bind(self, *, config: SecretMetadataHttpTransportConfig,
            transport: FortiPam191SecretCreateHttpTransport, create_binding: SecretCreate191WebBinding,
            execution_binding: SecretCreateM4ExecutionBinding, execution_store: PersistentM4ExecutionStateStore,
            onboarding_binding: WebSecretOnboardingBinding, runner: _SecretCreateRunner,
            reader: SecretCreate191ProjectionReader) -> WebSecretFixtureCaptureRunner:
        try:
            config.__post_init__()
            origin = urlsplit(config.base_url)
            if (origin.scheme != "https" or not origin.hostname
                    or origin.username is not None or origin.password is not None):
                raise ValueError
            if (transport._web_ack_capture != self.ack_capture
                    or self.ack_capture is not None and self.ack_capture.serial_digest != self.serial_digest):
                raise ValueError
            if (type(runner) is not _SecretCreateRunner or type(runner.runtime) is not ProtectedSecretCreateM4Runtime
                    or type(reader) is not SecretCreate191ProjectionReader
                    or type(onboarding_binding) is not WebSecretOnboardingBinding
                    or type(create_binding) is not SecretCreate191WebBinding
                    or type(execution_store) is not PersistentM4ExecutionStateStore):
                raise ValueError
            runtime = runner.runtime
            material = runtime._material_runtime
            if type(material) is not SecretCreateMaterialRuntime:
                raise ValueError
            adapter = material._adapter
            if (type(adapter) is not FortiPam191SecretCreatePrivateAdapter
                    or adapter._binding != create_binding
                    or type(adapter._transport) is not CentralLabSecretCreate191LeaseTransport
                    or adapter._transport._transport is not transport
                    or adapter._transport._provider is not material._coordinator._provider
                    or reader._transport is not cast(object, transport._metadata_transport)):
                raise ValueError
            plan = execution_binding.plan
            store_digest = canonical_digest({"database": str(execution_store._path),
                "key_file": str(execution_store._key_path), "key_digest": hashlib.sha256(execution_store._key).hexdigest()})
            if (runtime._projection_reader is not reader or runtime._execution_store is not execution_store
                    or store_digest != self.expected_store_digest
                    or runtime._resolve_binding(runner.authorization_ref) != execution_binding
                    or reader._binding != onboarding_binding or reader._target_binding != create_binding
                    or runner.onboarding_binding_digest != reader.inspect_onboarding_binding_digest()
                    or plan.expected_current_digest != reader._state_digest(exists=False)
                    or plan.expected_state_digest != reader._state_digest(exists=True)):
                raise ValueError
            reader._validate_plan(plan)
            record = WebSecretFixtureCreationRecord(config, transport=transport,
                create_binding=create_binding, execution_binding=execution_binding,
                execution_store=execution_store, serial_digest=self.serial_digest,
                expected_store_digest=self.expected_store_digest, directory=self.directory, key_file=self.key_file)
            return WebSecretFixtureCaptureRunner(runner, record)
        except Exception:
            raise WebSecretFixtureCaptureError(_ERROR) from None


class WebSecretFixtureCaptureRunner:
    """Run the accepted runner once, then seal evidence after original M4 success.

    A durable local attempt precedes the original runner. It permanently blocks
    another invocation using this directory, including after storage errors or
    restart. Capture failure leaves the original M4 terminal untouched and the
    attempt consumed; no second dispatch, unsigned adoption or cleanup follows.
    """

    def __init__(self, runner: _SecretCreateRunner, record: WebSecretFixtureCreationRecord) -> None:
        self.line_ref = runner.line_ref
        self.depends_on = runner.depends_on
        self._runner = runner
        self._record = record
        self._lock = threading.Lock()
        self._started = False
        self._result: dict[str, object] | None = None

    def __repr__(self) -> str:
        return "<WebSecretFixtureCaptureRunner redacted>"

    __str__ = __repr__

    def _reserve(self) -> None:
        directory = self._record._directory_fd()
        try:
            for name in ("creation.record", "creation.pending", "creation.ack"):
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError
            descriptor = os.open(_ATTEMPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(self._record._namespace.encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
            check = self._record._directory_fd()
            os.close(check)
        finally:
            os.close(directory)

    def execute_bound(self) -> Mapping[str, object]:
        with self._lock:
            if self._started:
                if self._result is None:
                    raise WebSecretFixtureCaptureError(_ERROR)
                return {**self._result, "idempotent_replay": True}
            self._started = True
            try:
                self._reserve()
                result = dict(self._runner.execute_bound())
                if result == {"outcome": "succeeded", "verification": "verified",
                              "compensation": "not_requested", "idempotent_replay": False}:
                    self._record.record_creation()
                self._result = result
                return dict(result)
            except Exception:
                raise WebSecretFixtureCaptureError(_ERROR) from None

    def read_creation(self) -> WebSecretFixtureCreationEvidence:
        """Read only the protected seal/M4; no create or native GET is invoked."""
        return self._record.read_creation()

    def read_acknowledged_creation(self) -> WebSecretFixtureAcknowledgedCreation:
        """Read only the original ACK/metadata seals and M4, without HTTP replay."""
        return self._record.read_acknowledged_creation()
