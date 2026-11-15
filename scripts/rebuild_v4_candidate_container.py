"""Create one isolated V4 candidate while preserving a source container's argv.

This deployment helper deliberately handles no credentials or secret values.
Its caller supplies owner-only Docker env files and already-prepared mounts.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from typing import cast
from urllib.parse import urlsplit


_SOURCE_NAME = re.compile(r"^(fortipam-mcp-http-v4-bp(?:006|007))-ready-candidate$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_STATE_DIRECTORY = "/var/lib/fortipam-mcp"
_SECRETS_DIRECTORY = "/run/secrets/v4"
_ONBOARDING_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_TOOLS_ENABLED"
)
_ONBOARDING_GATE_ENV = "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED"
_SECRET_BINDING_ENV = "FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE"
_CANDIDATE_EPHEMERAL_STATE_DIRECTORIES = (
    f"{_STATE_DIRECTORY}/sidecars",
    f"{_STATE_DIRECTORY}/private-runtime",
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--network-alias", required=True)
    parser.add_argument("--state-mount", required=True)
    parser.add_argument("--secrets-mount", required=True)
    parser.add_argument("--binding-mount", required=True)
    parser.add_argument("--env-file", action="append", required=True)
    return parser.parse_args()


def _source_config(source: str) -> dict[str, object]:
    raw = json.loads(
        subprocess.check_output(["docker", "inspect", source], text=True)
    )[0]["Config"]
    return cast(dict[str, object], raw)


def _validate_candidate_pair(source: str, candidate: str) -> None:
    match = _SOURCE_NAME.fullmatch(source)
    if match is None or candidate != f"{match.group(1)}-exec-candidate":
        raise ValueError(
            "candidate replacement is limited to the paired BP006/BP007 execution candidate"
        )


def _validate_proxy_pair(source: str, proxy: str) -> None:
    match = _SOURCE_NAME.fullmatch(source)
    if match is None:
        raise ValueError("candidate source is invalid")
    blueprint = source.removeprefix("fortipam-mcp-http-v4-").removesuffix(
        "-ready-candidate"
    )
    if proxy != f"fortipam-{blueprint}-mcp-tls-proxy":
        raise ValueError("candidate proxy is not the paired BP006/BP007 proxy")


def _load_environment_files(paths: list[str]) -> dict[str, str]:
    """Load Docker env files without echoing their protected values."""

    values: dict[str, str] = {}
    for raw_path in paths:
        try:
            lines = open(raw_path, encoding="utf-8").read().splitlines()
        except OSError as exc:
            raise ValueError("candidate environment is unavailable") from exc
        for line in lines:
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator or not _ENVIRONMENT_NAME.fullmatch(name):
                raise ValueError("candidate environment is invalid")
            if name == _ONBOARDING_GATE_ENV and name in values:
                raise ValueError("candidate onboarding Gate is defined more than once")
            values[name] = value
    return values


def _mount_parts(raw: str) -> tuple[str, str, str]:
    source, separator, remainder = raw.partition(":")
    destination, has_mode, mode = remainder.partition(":")
    if (
        not separator
        or not source.startswith("/")
        or not destination.startswith("/")
        or "," in source
        or "," in destination
    ):
        raise ValueError("candidate mount contract is invalid")
    if not has_mode:
        mode = "rw"
    if mode not in {"ro", "rw"}:
        raise ValueError("candidate mount contract is invalid")
    return source, destination, mode


def _bind_mount_arguments(raw: str) -> tuple[str, str]:
    """Use explicit bind mounts so Docker cannot create a missing source path."""

    source, destination, mode = _mount_parts(raw)
    specification = f"type=bind,source={source},target={destination}"
    if mode == "ro":
        specification += ",readonly"
    return "--mount", specification


def _container_exists(name: str) -> bool:
    return subprocess.run(
        ["docker", "inspect", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def _container_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _container_on_network(name: str, network: str) -> bool:
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            f'{{{{index .NetworkSettings.Networks "{network}"}}}}',
            name,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() not in {"", "<no value>"}


def _reload_proxy(name: str) -> None:
    """Validate and reload Nginx so Docker DNS follows the promoted candidate."""

    subprocess.run(
        ["docker", "exec", name, "nginx", "-t"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["docker", "exec", name, "nginx", "-s", "reload"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _application_ready(
    name: str,
    *,
    path: str,
    host: str,
    seconds: int = 30,
) -> bool:
    """Require the candidate HTTP application to reach its anonymous auth gate."""

    probe = (
        "import http.client,sys; "
        "connection=http.client.HTTPConnection('127.0.0.1',8000,timeout=2); "
        "connection.request('GET',sys.argv[1],headers={'Host':sys.argv[2]}); "
        "response=connection.getresponse(); "
        "raise SystemExit(0 if response.status == 401 else 1)"
    )
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _container_running(name):
            return False
        result = subprocess.run(
            ["docker", "exec", name, "python", "-c", probe, path, host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return True
        time.sleep(1)
    return False


def _validate_candidate_runtime_contract(
    environment: dict[str, str],
    *,
    user: str,
    state_mount: str,
    secrets_mount: str,
    binding_mount: str,
) -> None:
    """Reject a candidate whose OAuth origin or protected mounts drifted.

    This is intentionally a value-free preflight: it reads deployment inputs in
    process but never returns their values or copies protected state.
    """

    if user.split(":", 1)[0] in {"", "0", "root"}:
        raise ValueError("candidate user contract is invalid")
    user_parts = user.split(":", 1)
    if not user_parts[0].isdigit() or (
        len(user_parts) == 2 and (not user_parts[1] or not user_parts[1].isdigit())
    ):
        raise ValueError("candidate user contract is invalid")
    public_url = environment.get("FORTIPAM_MCP_HTTP_PUBLIC_URL")
    allowed_hosts = environment.get("FORTIPAM_MCP_HTTP_ALLOWED_HOSTS")
    database_path = environment.get("FORTIPAM_MCP_HTTP_LOCAL_OAUTH_DB")
    if (
        environment.get("FORTIPAM_MCP_HTTP_AUTH_MODE") != "local_oauth"
        or not public_url
        or not allowed_hosts
        or not database_path
    ):
        raise ValueError("candidate OAuth contract is incomplete")
    parsed_public = urlsplit(public_url)
    if (
        parsed_public.scheme != "https"
        or not parsed_public.netloc
        or not parsed_public.path
        or parsed_public.username
        or parsed_public.password
        or parsed_public.query
        or parsed_public.fragment
    ):
        raise ValueError("candidate OAuth public URL is invalid")
    if parsed_public.netloc not in {
        item.strip() for item in allowed_hosts.split(",") if item.strip()
    }:
        raise ValueError("candidate OAuth host contract is invalid")
    issuer = environment.get("FORTIPAM_MCP_HTTP_LOCAL_OAUTH_ISSUER")
    if issuer:
        parsed_issuer = urlsplit(issuer)
        if (
            parsed_issuer.scheme != "https"
            or parsed_issuer.netloc != parsed_public.netloc
            or not parsed_issuer.path.startswith(f"{parsed_public.path.rstrip('/')}/")
            or parsed_issuer.query
            or parsed_issuer.fragment
        ):
            raise ValueError("candidate OAuth issuer contract is invalid")
    if not database_path.startswith(f"{_STATE_DIRECTORY}/"):
        raise ValueError("candidate OAuth state path is invalid")
    _, state_destination, state_mode = _mount_parts(state_mount)
    _, secrets_destination, secrets_mode = _mount_parts(secrets_mount)
    _, binding_destination, binding_mode = _mount_parts(binding_mount)
    if (
        state_destination != _STATE_DIRECTORY
        or state_mode != "rw"
        or secrets_destination != _SECRETS_DIRECTORY
        or secrets_mode != "ro"
        or binding_mode != "ro"
        or not binding_destination.endswith(".json")
    ):
        raise ValueError("candidate mount contract is invalid")
    if environment.get(_ONBOARDING_FEATURE_ENV) != "true":
        raise ValueError("candidate onboarding Tool contract is invalid")
    if environment.get(_ONBOARDING_GATE_ENV) not in {"true", "false"}:
        raise ValueError("candidate onboarding Gate contract is invalid")
    if environment.get(_SECRET_BINDING_ENV) != binding_destination:
        raise ValueError("candidate onboarding binding contract is invalid")


def _candidate_tmpfs_arguments(user: str) -> tuple[str, ...]:
    """Keep candidate-only sidecar state out of the shared authority mount."""

    uid, separator, configured_gid = user.partition(":")
    gid = configured_gid if separator else uid
    options = f"rw,nosuid,nodev,noexec,size=16m,uid={uid},gid={gid},mode=0700"
    arguments: list[str] = []
    for directory in _CANDIDATE_EPHEMERAL_STATE_DIRECTORIES:
        arguments.extend(("--tmpfs", f"{directory}:{options}"))
    return tuple(arguments)


def main() -> None:
    args = _arguments()
    try:
        _validate_candidate_pair(args.source, args.candidate)
        _validate_proxy_pair(args.source, args.proxy)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    config = _source_config(args.source)
    entrypoint = config.get("Entrypoint")
    command = config.get("Cmd")
    if (
        not isinstance(entrypoint, list)
        or not entrypoint
        or not all(isinstance(item, str) for item in entrypoint)
        or not isinstance(command, list)
        or len(command) < 2
        or command[0] != "-ceu"
        or not all(isinstance(item, str) for item in command)
    ):
        raise SystemExit("source startup contract is not the supported shell argv")
    image = config.get("Image")
    user = config.get("User")
    workdir = config.get("WorkingDir")
    if (
        not isinstance(image, str)
        or not image
        or not isinstance(user, str)
        or not user
        or not isinstance(workdir, str)
        or not workdir
    ):
        raise SystemExit("source container lacks required image, user, or workdir")
    try:
        environment = _load_environment_files(args.env_file)
        _validate_candidate_runtime_contract(
            environment,
            user=user,
            state_mount=args.state_mount,
            secrets_mount=args.secrets_mount,
            binding_mount=args.binding_mount,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    public_url = environment["FORTIPAM_MCP_HTTP_PUBLIC_URL"]
    parsed_public_url = urlsplit(public_url)

    replacement = f"{args.candidate}-replacement"
    previous = f"{args.candidate}-previous"
    if _container_exists(replacement) or _container_exists(previous):
        raise SystemExit("candidate replacement has unresolved recovery state")
    candidate_exists = _container_exists(args.candidate)
    candidate_was_running = candidate_exists and _container_running(args.candidate)
    candidate_was_connected = candidate_exists and _container_on_network(
        args.candidate, args.network
    )
    if not _container_running(args.proxy) or not _container_on_network(
        args.proxy, args.network
    ):
        raise SystemExit("candidate proxy is unavailable")
    command_line = [
        "docker",
        "create",
        "--name",
        replacement,
        "--network",
        args.network,
        "--network-alias",
        f"{args.network_alias}-replacement",
        "--user",
        user,
        "--workdir",
        workdir,
        *_candidate_tmpfs_arguments(user),
    ]
    for env_file in args.env_file:
        command_line.extend(("--env-file", env_file))
    command_line.extend(
        (
            *_bind_mount_arguments(args.secrets_mount),
            *_bind_mount_arguments(args.binding_mount),
            *_bind_mount_arguments(args.state_mount),
            "--entrypoint",
            entrypoint[0],
            image,
            *entrypoint[1:],
            *command,
        )
    )
    old_moved = False
    replacement_promoted = False
    try:
        subprocess.run(command_line, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(
            ["docker", "start", replacement],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        if not _application_ready(
            replacement,
            path=parsed_public_url.path,
            host=parsed_public_url.netloc,
        ):
            raise RuntimeError("replacement failed application readiness")
        subprocess.run(
            ["docker", "stop", replacement],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["docker", "network", "disconnect", args.network, replacement],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "docker",
                "network",
                "connect",
                "--alias",
                args.network_alias,
                args.network,
                replacement,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        if candidate_exists:
            subprocess.run(
                ["docker", "rename", args.candidate, previous],
                check=True,
            )
            old_moved = True
            if candidate_was_connected:
                subprocess.run(
                    ["docker", "network", "disconnect", args.network, previous],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
        subprocess.run(
            ["docker", "rename", replacement, args.candidate],
            check=True,
        )
        replacement_promoted = True
        subprocess.run(
            ["docker", "start", args.candidate],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        if not _application_ready(
            args.candidate,
            path=parsed_public_url.path,
            host=parsed_public_url.netloc,
        ):
            raise RuntimeError("candidate failed application readiness")
        _reload_proxy(args.proxy)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        proxy_reconciled = True
        if old_moved:
            subprocess.run(
                ["docker", "rm", "-f", args.candidate],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            subprocess.run(
                ["docker", "rename", previous, args.candidate],
                check=True,
            )
            if candidate_was_connected:
                subprocess.run(
                    [
                        "docker",
                        "network",
                        "connect",
                        "--alias",
                        args.network_alias,
                        args.network,
                        args.candidate,
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
            if candidate_was_running:
                subprocess.run(
                    ["docker", "start", args.candidate],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
            try:
                _reload_proxy(args.proxy)
            except subprocess.CalledProcessError:
                proxy_reconciled = False
        else:
            subprocess.run(
                [
                    "docker",
                    "rm",
                    "-f",
                    args.candidate if replacement_promoted else replacement,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        if not proxy_reconciled:
            raise SystemExit(
                "candidate replacement was rejected; prior state restored but proxy requires reconciliation"
            ) from exc
        raise SystemExit("candidate replacement was rejected; prior state preserved") from exc
    if old_moved:
        subprocess.run(
            ["docker", "rm", "-f", previous],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    print("candidate_created=true")


if __name__ == "__main__":
    main()
