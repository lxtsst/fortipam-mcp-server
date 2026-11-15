"""Private build-29 description delta compiler, without dispatch authority.

The caller must obtain a freshly qualified, formatted metadata read and bind
its identity privately. The schema establishes the description field only;
partial PUT preservation and permissions still require laboratory acceptance.
"""

from collections.abc import Mapping


MAX_DESCRIPTION_BYTES = 1023
_UNAVAILABLE = "The fixed Secret description update is unavailable."
_IDENTITY = {"id", "name", "folder", "template"}
_READ_FIELDS = _IDENTITY | {"description", "q_origin_key"}


class SecretDescriptionUpdateContractError(ValueError):
    """Non-disclosing rejection of an unqualified metadata delta."""


def project_secret_description_metadata(prewrite: object) -> dict[str, object]:
    """Extract only fixed metadata after the reader's pre-decode redaction.

    Build-29 Owner GET can ignore format and return the complete record. Never
    copy that record into a write; unknown fields do not establish preservation.
    """
    try:
        if not isinstance(prewrite, Mapping):
            raise ValueError
        row = prewrite.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping) or row.get("field") is not None:
            raise ValueError
        return {
            **{key: prewrite.get(key) for key in (
                "version", "build", "status", "http_method", "http_status", "path", "name",
            )},
            "results": {key: row[key] for key in _READ_FIELDS if key in row},
        }
    except Exception:
        raise SecretDescriptionUpdateContractError(_UNAVAILABLE) from None


def compile_secret_description_update_body(
    prewrite: object,
    *,
    expected_secret_id: int,
    expected_name: str,
    expected_folder_id: int,
    expected_template: str,
    description: str,
) -> dict[str, str | int]:
    """Compile only description plus unchanged routing identity, never fields.

    No network request, claim, confirmation, or authorization occurs here.
    Use only inside a private adapter; the returned selectors are not MCP output.
    """
    try:
        if not isinstance(prewrite, Mapping) or any(
            prewrite.get(key) != value for key, value in {
                "version": "v7.0.0", "build": 29,
                "http_method": "GET", "http_status": 200,
                "path": "secret", "name": "database",
            }.items()
        ) or type(prewrite.get("build")) is not int or prewrite.get("status") not in {
            "success", "OK",
        }:
            raise ValueError
        identity: dict[str, str | int] = {
            "id": expected_secret_id, "name": expected_name,
            "folder": expected_folder_id, "template": expected_template,
        }
        for key in ("id", "folder"):
            number = identity[key]
            if type(number) is not int or not 0 < number <= 2_147_483_647:
                raise ValueError
        for key in ("name", "template"):
            value = identity[key]
            if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > (79 if key == "template" else 255)
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise ValueError
        row = prewrite.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if (not isinstance(row, Mapping) or not _IDENTITY.issubset(row)
                or not set(row).issubset(_READ_FIELDS)
                or any(type(row.get(key)) is not type(value) or row[key] != value
                       for key, value in identity.items())
                or type(row.get("q_origin_key", expected_secret_id)) not in {int, str}
                or row.get("q_origin_key", expected_secret_id) not in {
                    expected_secret_id, str(expected_secret_id),
                }):
            raise ValueError
        for description_value in (row.get("description"), description):
            if (not isinstance(description_value, str)
                    or len(description_value.encode("utf-8")) > MAX_DESCRIPTION_BYTES
                    or any(ord(char) < 32 or ord(char) == 127 for char in description_value)):
                raise ValueError
        if row["description"] == description:
            raise ValueError
        return {**identity, "description": description}
    except Exception:
        raise SecretDescriptionUpdateContractError(_UNAVAILABLE) from None
