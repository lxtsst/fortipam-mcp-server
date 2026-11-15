FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ARG APP_WHEEL=dist/fortipam_mcp_server-4.0.0b108-py3-none-any.whl
ARG APP_WHEEL_SHA256

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 fortipam-mcp \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin fortipam-mcp

COPY deploy/docker/runtime-constraints.txt /tmp/runtime-constraints.txt
COPY deploy/docker/wheelhouse-manifest.sha256 /tmp/wheelhouse-manifest.sha256
COPY deploy/docker/wheelhouse/ /tmp/wheelhouse/
COPY ${APP_WHEEL} /tmp/fortipam_mcp_server-4.0.0b108-py3-none-any.whl

RUN test -n "${APP_WHEEL_SHA256}" \
    && test "$(sha256sum /tmp/fortipam_mcp_server-4.0.0b108-py3-none-any.whl | cut -d ' ' -f 1)" = "${APP_WHEEL_SHA256}" \
    && cp /tmp/fortipam_mcp_server-4.0.0b108-py3-none-any.whl /tmp/wheelhouse/ \
    && cd /tmp/wheelhouse \
    && sha256sum --check /tmp/wheelhouse-manifest.sha256 \
    && rm /tmp/wheelhouse/fortipam_mcp_server-4.0.0b108-py3-none-any.whl \
    && cd / \
    && python -m pip install \
      --no-index \
      --find-links /tmp/wheelhouse \
      --constraint /tmp/runtime-constraints.txt \
      /tmp/fortipam_mcp_server-4.0.0b108-py3-none-any.whl \
    && rm -rf /tmp/fortipam_mcp_server-4.0.0b108-py3-none-any.whl /tmp/runtime-constraints.txt /tmp/wheelhouse-manifest.sha256 /tmp/wheelhouse

LABEL org.opencontainers.image.fortipam.app-wheel-sha256="${APP_WHEEL_SHA256}"

USER 10001:10001
WORKDIR /opt/fortipam-mcp

ENTRYPOINT ["fortipam-mcp-http"]
