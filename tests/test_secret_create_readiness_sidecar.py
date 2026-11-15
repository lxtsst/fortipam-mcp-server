from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.secret_create_readiness_sidecar import (
    SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV,
    SECRET_CREATE_READINESS_PROXY_REF,
    SECRET_CREATE_READINESS_SOCKET_ENV,
    SecretCreateReadinessSidecarError,
    SecretCreateReadinessSidecarSettings,
    UnixSecretCreateReadinessProxyClient,
    UnixSecretCreateReadinessProxyClientSettings,
    create_secret_create_readiness_sidecar_app,
    secret_create_readiness_sidecar_settings_from_environment,
)
from fortipam_mcp.secret_create_runtime_sidecar import (
    SECRET_CREATE_RUNTIME_REF,
    SecretCreateRuntimeSidecarError,
    UnixSecretCreateRuntimeClientSettings,
    UnixSecretCreateRuntimeReadinessProbe,
)


def test_readiness_app_has_no_execution_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = UnixSecretCreateRuntimeReadinessProbe(
        UnixSecretCreateRuntimeClientSettings(tmp_path / "private.sock")
    )
    monkeypatch.setattr(
        UnixSecretCreateRuntimeReadinessProbe,
        "verify_ready",
        lambda self: None,
    )
    with TestClient(create_secret_create_readiness_sidecar_app(probe)) as client:
        ready = client.post(
            "/v1/secret-create-readiness/ready",
            json={"readiness_proxy_ref": SECRET_CREATE_READINESS_PROXY_REF},
        )
        extended = client.post(
            "/v1/secret-create-readiness/ready",
            json={
                "readiness_proxy_ref": SECRET_CREATE_READINESS_PROXY_REF,
                "extra": True,
            },
        )
        runtime_shaped = client.post(
            "/v1/secret-create-runtime/ready",
            json={"runtime_ref": SECRET_CREATE_RUNTIME_REF},
        )
        execute = client.post(
            "/v1/secret-create-runtime/execute",
            json={"runtime_ref": SECRET_CREATE_RUNTIME_REF},
        )

    assert ready.status_code == 204 and not ready.content
    assert extended.status_code == 409
    assert extended.json() == {"status": "rejected"}
    assert runtime_shaped.status_code == 404
    assert execute.status_code == 404


def test_readiness_app_maps_private_runtime_outage_to_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = UnixSecretCreateRuntimeReadinessProbe(
        UnixSecretCreateRuntimeClientSettings(tmp_path / "private.sock")
    )

    def unavailable(self: UnixSecretCreateRuntimeReadinessProbe) -> None:
        del self
        raise SecretCreateRuntimeSidecarError("unavailable")

    monkeypatch.setattr(
        UnixSecretCreateRuntimeReadinessProbe,
        "verify_ready",
        unavailable,
    )
    with TestClient(create_secret_create_readiness_sidecar_app(probe)) as client:
        response = client.post(
            "/v1/secret-create-readiness/ready",
            json={"readiness_proxy_ref": SECRET_CREATE_READINESS_PROXY_REF},
        )

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_readiness_settings_require_distinct_absolute_sockets(tmp_path: Path) -> None:
    environment = {
        SECRET_CREATE_READINESS_SOCKET_ENV: str(tmp_path / "readiness.sock"),
        SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV: str(tmp_path / "private.sock"),
    }
    settings = secret_create_readiness_sidecar_settings_from_environment(environment)
    assert settings == SecretCreateReadinessSidecarSettings(
        tmp_path / "readiness.sock",
        tmp_path / "private.sock",
    )
    with pytest.raises(SecretCreateReadinessSidecarError, match="incomplete"):
        secret_create_readiness_sidecar_settings_from_environment({})
    with pytest.raises(SecretCreateReadinessSidecarError, match="invalid"):
        SecretCreateReadinessSidecarSettings(
            tmp_path / "same.sock",
            tmp_path / "same.sock",
        )
    with pytest.raises(SecretCreateReadinessSidecarError, match="invalid"):
        SecretCreateReadinessSidecarSettings(
            Path("readiness.sock"),
            tmp_path / "private.sock",
        )
    with pytest.raises(SecretCreateReadinessSidecarError, match="invalid"):
        UnixSecretCreateReadinessProxyClientSettings(Path("readiness.sock"))
    proxy_client = UnixSecretCreateReadinessProxyClient(
        UnixSecretCreateReadinessProxyClientSettings(
            tmp_path / "unavailable-readiness.sock"
        )
    )
    assert proxy_client.is_available() is False
    assert not hasattr(proxy_client, "execute_once")
