"""Fixed, value-minimized execution evidence for one newly owned Job."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import quote

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .job_definition_owned_workflow import JobDefinitionOwnedWorkflow
from .job_definition_detail_reader import _token
from .target_preservation_contract import _token_digest
from .target_api_dependency_reader import _private_http_logs
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _redact_json_field_values, _zeroize_mutable
from .target_lifecycle_dependencies import _one, _spans
from .target_ssh_transport import _send_and_read, _close_cli
from .folder_namespace_ssh_reader import _frame_lines, _SERIAL_COMMAND

SCRIPT = "echo BP008_JOB_OK"
UTC8 = timezone(timedelta(hours=8))
_ERROR = "The fixed owned Job execution evidence is unavailable."


@dataclass(frozen=True, repr=False)
class JobExecutionSnapshot(_OpaqueC3Object):
    tokens: dict[str, str]
    digest: str
    start: int
    end: int
    marker: bool
    enabled: bool
    scheduled_at: int
    updated_at: int


class JobExecutionObservationPending(ValueError):
    """Only known runtime fields changed inside one read-only bracket."""


class JobExecutionSources:
    def __init__(self, definition: JobDefinitionOwnedWorkflow, target: dict[str, Any]):
        if type(definition) is not JobDefinitionOwnedWorkflow or definition.phase != "recover" or definition._original is None:
            raise ValueError(_ERROR)
        original = definition._original.inspect_original_full_state()
        if (original.original_ack.original_outcome != "succeeded" or original.original_ack.original_verification != "verified"
                or not definition._original._store._read_only):
            raise ValueError(_ERROR)
        if definition.source._body["script"] != SCRIPT:raise ValueError(_ERROR)
        self.definition, self.base, self.original = definition, definition.source, definition._original
        self.target = target
        self._source = self.base.source_context_digest
        self._initial_state = original.state_digest
        self._closed = False
        self.logout_verified = False

    def live(self) -> None:
        self.definition._live()
        if self._closed or self.base.source_context_digest != self._source:
            raise ValueError(_ERROR)

    def _read(self, path: str, *, collection: bool = False, secret: bool = False) -> bytearray:
        client = self.base._owner._client
        if client is None:raise ValueError(_ERROR)
        raw = bytearray()
        headers = {"Accept":"application/json", "Accept-Encoding":"identity", "Cache-Control":"no-store"}
        if collection:
            csrf = client.cookies.get("ccsrftoken")
            if type(csrf) is not str or not csrf or any(c in csrf for c in "\r\n"):raise ValueError(_ERROR)
            headers.update({"X-HTTP-Method-Override":"GET", "X-CSRFTOKEN":csrf.strip('"'), "Content-Type":"application/json"})
        try:
            with client.stream("POST" if collection else "GET", path, headers=headers,
                    content=b'{"json_filter":[]}' if collection else None) as response:
                if (response.status_code != 200 or response.headers.get("content-type","").split(";",1)[0] != "application/json"
                        or response.headers.get("content-encoding","identity") not in ("", "identity")):
                    raise ValueError(_ERROR)
                for chunk in response.iter_bytes():
                    if len(raw)+len(chunk)>1048576:raise ValueError(_ERROR)
                    raw.extend(chunk)
            if secret:_redact_json_field_values(raw)
            _spans(raw)
            result, raw = raw, bytearray()
            return result
        finally:_zeroize_mutable(raw)

    def _row(self, raw: bytearray, table: str, *, collection: bool = False) -> tuple[int,int]:
        fields = _spans(raw)
        wanted = {"version":"v7.0.0", "build":29, "http_status":200, "http_method":"POST" if collection else "GET",
            "path":"secret", "name":table, "vdom":"root", "serial":self.base._serial}
        for key,value in wanted.items():
            actual = m._scalar(raw,fields[key])
            if type(actual) is not type(value) or actual != value:raise ValueError(_ERROR)
        status = m._scalar(raw,fields["status"])
        if status not in ({"OK"} if collection or table == "database" else {"success"}):raise ValueError(_ERROR)
        if "error" in fields:
            error=m._scalar(raw,fields["error"])
            if error is not None and (type(error) is not int or error!=0):raise ValueError(_ERROR)
        if not collection:return _one(raw,fields["results"])
        span = fields["results"];matches=[]
        for row in m._array(raw,span,512):
            selected = m._object_spans(raw,*row,frozenset({"name"}))
            if m._scalar(raw,selected["name"]) == self.base._candidate._name:matches.append(row)
        if len(matches) != 1:raise ValueError(_ERROR)
        return matches[0]

    def _metadata(self, path: str, table: str, keys: tuple[str,...]) -> tuple[dict[str,Any],str]:
        if table == "target":
            # Target ACLs are evaluated for the actual API writer.  A separate
            # SuperOwner session does not inherit that writer's ownership.
            with _private_http_logs(), self.base._factory(verify=self.base._tls,timeout=10,trust_env=False,follow_redirects=False) as client:
                try:raw = self.base._get(client,path,self.base._now()+10)
                finally:client.cookies.clear()
        else:
            raw = self._read(path,secret=table == "database")
        try:
            fields = m._object_spans(raw,*self._row(raw,table),frozenset(keys))
            values = {key: ("empty" if b"".join(raw[slice(*fields[key])].split()) == b"[]" else "populated")
                if key == "service-addrs" else m._scalar(raw,fields[key]) for key in keys}
            digest = hashlib.sha256(b"".join(key.encode()+_token_digest(raw,fields[key]).encode() for key in sorted(keys))).hexdigest()
            return values,digest
        finally:_zeroize_mutable(raw)

    def _target(self) -> str:
        keys: tuple[str,...] = ("id","target","template","ssh-service-status","need-approval-job","approval-profile")
        path = "/api/v2/cmdb/secret/database/"+str(self.base._body["secret"])+"?format="+quote("|".join(keys),safe="")+"&with_meta=true&vdom=root"
        secret,secret_digest = self._metadata(path,"database",keys)
        if (secret["id"] != self.base._body["secret"] or secret["target"] != self.target["target_name"]
                or secret["template"] != self.target["secret_template"] or secret["ssh-service-status"] != "up"
                or secret_digest != self.target["secret_target_digest"]):raise ValueError(_ERROR)
        keys = ("name","address","template","service-addrs")
        path = "/api/v2/cmdb/secret/target/"+quote(self.target["target_name"],safe="")+"?format="+quote("|".join(keys),safe="")+"&with_meta=true&vdom=root"
        target,digest = self._metadata(path,"target",keys)
        if (target != {"name":self.target["target_name"],"address":self.target["target_address"],
                "template":self.target["target_template"],"service-addrs":"empty"} or digest != self.target["target_digest"]):
            raise ValueError(_ERROR)
        return canonical_digest((secret_digest,digest))

    def clock(self) -> int:
        self.live()
        async def read() -> int:
            channel = self.base._namespace_proto._ssh
            async with channel._connection() as connection:
                process,prompt,deadline = await channel._open_cli(connection)
                try:
                    raw = await _send_and_read(process,_SERIAL_COMMAND,prompt,deadline)
                    if tuple(x for x in _frame_lines(raw,_SERIAL_COMMAND,prompt) if x.strip()) != (b"Serial-Number: "+self.base._serial.encode(),):raise ValueError(_ERROR)
                    command = 'get system status | grep "System time"'
                    raw = await _send_and_read(process,command,prompt,deadline)
                    lines = tuple(x for x in _frame_lines(raw,command,prompt) if x.strip())
                    if len(lines) != 1 or not lines[0].startswith(b"System time: "):raise ValueError(_ERROR)
                    parsed = datetime.strptime(lines[0][13:].decode("ascii").strip(),"%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC8)
                    value = int(parsed.timestamp())
                    if abs(time.time()-value)>5:raise ValueError(_ERROR)
                    return value
                finally:await _close_cli(process)
        return asyncio.run(read())

    def pristine(self) -> tuple[dict[str,str],str]:
        self.live()
        observed = self.base.observe_candidate_presence()
        if observed.state_digest != self._initial_state:raise ValueError(_ERROR)
        snapshot,dependency = self.snapshot(self.base._body,pristine=True)
        return snapshot.tokens,dependency

    def _rights(self) -> str:
        with self.base._factory(verify=self.base._tls,timeout=10,trust_env=False,follow_redirects=False) as client:
            try:return self.base._writer_role(client,time.monotonic()+15)
            finally:client.cookies.clear()

    def snapshot(self, expected_body: dict[str,Any], *, pristine: bool = False) -> tuple[JobExecutionSnapshot,str]:
        self.live()
        buffers=[]
        try:
            rights=self._rights()
            with self.base._owner.authenticated():
                deadline=time.monotonic()+30
                before=self.base._owner_role(deadline)
                policy=self.base._secret_dependency(deadline);target=self._target()
                path=self.base._candidate._metadata_path
                first=self._read(path);buffers.append(first)
                row=self._row(first,"job");fields=_object_spans(first,*row)
                for key,value in expected_body.items():
                    if key != "$originalName" and _token_digest(first,fields[key]) != hashlib.sha256(_token(value)).hexdigest():raise ValueError(_ERROR)
                reference=m._scalar(first,fields["q_ref"])
                if (m._scalar(first,fields["approval-status"]) != "approved" or type(reference) is not int
                        or reference != 0 or m._scalar(first,fields["q_static"]) is not False):raise ValueError(_ERROR)
                tokens={key:_token_digest(first,span) for key,span in fields.items()}
                updated=m._scalar(first,fields["updated-time"])
                if type(updated) is not str:raise ValueError(_ERROR)
                updated_at=int(datetime.strptime(updated,"%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC8).timestamp())
                collection=self._read("/api/v2/cmdb/secret/job?with_meta=true&vdom=root",collection=True);buffers.append(collection)
                selected=m._object_spans(collection,*self._row(collection,"job",collection=True),frozenset({"name","user","secret","script","status","approval-status","schedule","type","scheduled-time","execution-time-start","execution-time-end","result-txt"}))
                for key in ("name","user","secret","script","status","schedule","type"):
                    actual=m._scalar(collection,selected[key])
                    if type(actual) is not type(expected_body[key]) or actual != expected_body[key]:raise ValueError(_ERROR)
                if m._scalar(collection,selected["approval-status"]) != "approved":raise ValueError(_ERROR)
                start=m._scalar(collection,selected["execution-time-start"]);end=m._scalar(collection,selected["execution-time-end"])
                scheduled=m._scalar(collection,selected["scheduled-time"])
                if (type(start) is not int or type(end) is not int or type(scheduled) is not int
                        or start<0 or end<0 or scheduled<0 or end and (not start or end<start)):raise ValueError(_ERROR)
                output=m._scalar(collection,selected["result-txt"])
                if type(output) is not str:raise ValueError(_ERROR)
                pending=_token_digest(first,fields["result-txt"])!=_token_digest(collection,selected["result-txt"])
                # Native SSH output retains SGR and bracketed-paste modes.
                # Remove only these zero-width wrappers, without interpreting
                # cursor, backspace, OSC or other terminal operations as output.
                rendered=re.sub(r"\x1b\[[0-9;]*m","",output)
                for control in ("\x1b[?2004h","\x1b[?2004l"):
                    rendered=rendered.replace(control,"")
                marker="BP008_JOB_OK" in rendered.splitlines() and SCRIPT not in rendered
                if pristine and (start or end or output):raise ValueError(_ERROR)
                second=self._read(path);buffers.append(second)
                fields2=_object_spans(second,*self._row(second,"job"))
                tokens2={key:_token_digest(second,span) for key,span in fields2.items()}
                changed={key for key in tokens.keys()|tokens2.keys() if tokens.get(key)!=tokens2.get(key)}
                if changed-{"execution-time-start","execution-time-end","result-txt","updated-time"}:raise ValueError(_ERROR)
                pending=pending or bool(changed)
                if self._target()!=target or self.base._secret_dependency(deadline)!=policy or self.base._owner_role(deadline)!=before:raise ValueError(_ERROR)
            self.logout_verified=self.base._owner.logout_verified
            if not self.logout_verified:raise ValueError(_ERROR)
            if self._rights()!=rights:raise ValueError(_ERROR)
            if pending:raise JobExecutionObservationPending(_ERROR)
            return JobExecutionSnapshot(tokens,canonical_digest(tokens),start,end,marker,expected_body["status"]=="enable",scheduled,updated_at),canonical_digest((policy,target,rights))
        finally:
            for raw in buffers:_zeroize_mutable(raw)

    def close(self) -> None:
        self._closed=True;self.definition.close()
