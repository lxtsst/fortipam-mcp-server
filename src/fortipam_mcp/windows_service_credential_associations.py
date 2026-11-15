"""Private fixed non-material Secret relationship framing, never source authority.

Reuse build29's qualified escaped-alternation grep grammar. Unselected table
headers/entry anchors preserve scope while field values are never selected.
Omitted association flags and dependency sections remain unknown; this parser
does not infer defaults, freshness, permissions, activity or original custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from v4_planning.material_provider import _OpaqueC3Object

from .secret_namespace_ssh_reader import _safe_secret_name

_ERROR = "The private service credential association projection is unavailable."
GROUPED_COMMAND = 'show full-configuration | grep "' + r"\|".join((
    "^config secret database$", "^    edit ", "^        set name ",
    "^        set target ", "^        set associated-secret ",
    "^        set target-privilege-account ", "^        config ",
    "^            edit ", "^                set target ", "^                set updater ",
    "^            next$", "^        end$", "^    next$", "^end$",
)) + '"'


class WindowsServiceAssociationError(ValueError):
    """Fixed refusal without native values or partial relationships."""


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAssociationDependency(_OpaqueC3Object):
    identifier: int
    target: str
    updater: str


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAssociationSecret(_OpaqueC3Object):
    identifier: int
    name: str
    target: str
    associated_secret_id: int | None
    privileged: bool | None
    dependencies: tuple[ServiceAssociationDependency, ...] | None


def _integer(token: bytes, *, maximum: int = 2147483647, zero: bool = False) -> int:
    if re.fullmatch(rb"0|[1-9][0-9]{0,9}" if zero else rb"[1-9][0-9]{0,9}", token) is None:
        raise ValueError
    value = int(token)
    if value > maximum:
        raise ValueError
    return value


def _text(token: bytes, *, maximum: int, empty: bool = False) -> str:
    if empty and token in (b'""', b"''"):
        return ""
    match = re.fullmatch(rb'"([^"\\\r\n]*)"', token)
    if match is None:
        raise ValueError
    value = match[1].decode("utf-8")
    if not _safe_secret_name(value) or len(value.encode("utf-8")) > maximum:
        raise ValueError
    return value


def project_service_association_columns(lines: tuple[bytes, ...]) -> tuple[ServiceAssociationSecret, ...]:
    """Join only structurally closed compiled columns, preserving unknowns."""
    try:
        if (type(lines) is not tuple or any(type(line) is not bytes for line in lines)
                or not 2 <= len(lines) <= 16384 or sum(map(len, lines)) > 262144
                or lines[0] != b"config secret database" or lines[-1] != b"end"):
            raise ValueError
        rows: list[ServiceAssociationSecret] = []
        current: dict[str, object] | None = None
        section: bytes | None = None
        dependency: dict[str, object] | None = None
        dependencies: list[ServiceAssociationDependency] | None = None
        sections: set[bytes] = set()
        skipped_entry = False
        for line in lines[1:-1]:
            if line.startswith(b"    edit "):
                if current is not None:
                    raise ValueError
                current = {"id": _integer(line[len(b"    edit "):])}
                dependencies = None
                sections = set()
            elif line == b"    next":
                if current is None or section is not None or dependency is not None or len(rows) >= 128:
                    raise ValueError
                identifier, name, target = current["id"], current["name"], current["target"]
                associated, privileged = current.get("associated"), current.get("privileged")
                if (type(identifier) is not int or type(name) is not str or type(target) is not str
                        or associated is not None and type(associated) is not int
                        or privileged is not None and type(privileged) is not bool):
                    raise ValueError
                rows.append(ServiceAssociationSecret(identifier, name, target, associated, privileged,
                    None if dependencies is None else tuple(dependencies)))
                current = None
            elif current is None:
                raise ValueError
            elif line.startswith(b"        config "):
                table = line[len(b"        config "):]
                if (section is not None or table in sections
                        or re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", table) is None):
                    raise ValueError
                section = table
                sections.add(table)
                if table == b"dependency":
                    dependencies = []
            elif line == b"        end":
                if section is None or dependency is not None or skipped_entry:
                    raise ValueError
                section = None
            elif section is not None:
                if section != b"dependency":
                    if line.startswith(b"            edit ") and not skipped_entry:
                        _integer(line[len(b"            edit "):])
                        skipped_entry = True
                    elif line == b"            next" and skipped_entry:
                        skipped_entry = False
                    else:
                        raise ValueError
                    continue
                if line.startswith(b"            edit "):
                    if dependency is not None:
                        raise ValueError
                    dependency = {"id": _integer(line[len(b"            edit "):], maximum=64)}
                elif line == b"            next":
                    if dependency is None or dependencies is None or len(dependencies) >= 64:
                        raise ValueError
                    dep_id, target, updater = dependency["id"], dependency["target"], dependency["updater"]
                    if type(dep_id) is not int or type(target) is not str or type(updater) is not str:
                        raise ValueError
                    if any(item.identifier == dep_id for item in dependencies):
                        raise ValueError
                    dependencies.append(ServiceAssociationDependency(dep_id, target, updater))
                    dependency = None
                elif dependency is not None:
                    if line.startswith(b"                set target ") and "target" not in dependency:
                        dependency["target"] = _text(line[len(b"                set target "):], maximum=127)
                    elif line.startswith(b"                set updater ") and "updater" not in dependency:
                        dependency["updater"] = _text(line[len(b"                set updater "):], maximum=79)
                    else:
                        raise ValueError
                else:
                    raise ValueError
            elif line.startswith(b"        set name ") and "name" not in current:
                current["name"] = _text(line[len(b"        set name "):], maximum=255)
            elif line.startswith(b"        set target ") and "target" not in current:
                current["target"] = _text(line[len(b"        set target "):], maximum=127, empty=True)
            elif line.startswith(b"        set associated-secret ") and "associated" not in current:
                current["associated"] = _integer(line[len(b"        set associated-secret "):], zero=True)
            elif line.startswith(b"        set target-privilege-account ") and "privileged" not in current:
                token = line[len(b"        set target-privilege-account "):]
                if token not in (b"enable", b"disable"):
                    raise ValueError
                current["privileged"] = token == b"enable"
            else:
                raise ValueError
        if (current is not None or section is not None or dependency is not None or skipped_entry or not rows
                or len({row.identifier for row in rows}) != len(rows)
                or len({row.name for row in rows}) != len(rows)):
            raise ValueError
        return tuple(rows)
    except Exception:
        raise WindowsServiceAssociationError(_ERROR) from None
