"""Inactive fixed Target creator with original ACK persistence and sealed evidence.

The caller must independently qualify the proposed body, actor/dependencies,
M4 authority and cleanup plan. No existing object may be adopted. A consumed or
uncertain create cannot be replayed. No public Tool or runtime wiring exists.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import time
from typing import Any, Literal, TYPE_CHECKING
from urllib.parse import quote, urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from . import secret_bulk_import_metadata as m
from . import target_creation_evidence as e
from . import target_preservation_contract as c
from .ldap_server_http_transport import _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable, _json_value_end, _skip_json_space
from .target_operation_records import _TargetOperationRecords
from .windows_target_owner_source import WindowsTargetOwnerSource

if TYPE_CHECKING:
    from .windows_target_owner_recovery import WindowsTargetOwnerRecovery

_ERROR = 'Protected Target creation transport unavailable.'
_CONTRACT = 'fortipam-build29-target-create-v1'
_LIMIT = 2 * 1048576
_PATH = '/api/v2/cmdb/secret/target'
_DOMAIN = b'fortipam-build29-target-created-evidence-v1\x00'


class TargetCreationTransportError(RuntimeError):
    """Stable refusal; any failed POST remains potentially applied."""


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _verify_body(body: bytearray, proposal: c.TargetState) -> None:
    if type(body) is not bytearray or not 0 < len(body) <= _LIMIT:
        raise ValueError
    start = _skip_json_space(body,0); end = _json_value_end(body,start)
    if _skip_json_space(body,end) != len(body): raise ValueError
    m._validate_json(body,start,end,depth=0,budget=[50000])
    required = c.TARGET_STATE_FIELDS - e._GENERATED
    spans = m._object_spans(body,start,end,required | {'$originalName'})
    if set(spans) != required | {'$originalName'} or c._member_count(body,(start,end)) != len(spans):
        raise ValueError
    if m._scalar(body,spans['$originalName']) != proposal.name: raise ValueError
    fingerprints = dict(proposal.field_digests)
    for key in required:
        actual = (c._digest(m._scalar(body,spans[key])) if key in ('name',*c._COORDINATES)
                  else c._token_digest(body,spans[key]))
        if actual != fingerprints[key]: raise ValueError



def _verify_request(body: bytearray, proposal: c.TargetState,
                    expected_material: bytearray | None = None) -> str | None:
    if expected_material is None:
        _verify_body(body, proposal)
        return None
    compiled = bytearray()
    try:
        from .target_creation_serializer import (
            CONTRACT, WINDOWS_EXECUTION_CONTRACT, JOB_MAPPED_CONTRACT, compile_request, compile_windows_execution_target_request, compile_job_mapped_target_request,
            SERVICE_ACCOUNT_CONTRACT, compile_service_account_target_request,
            SERVICE_ACCOUNT_REFERENCE_CONTRACT, compile_service_account_reference_target_request,
        )
        if type(body) is not bytearray or type(expected_material) is not bytearray:
            raise ValueError
        material_digest = hashlib.sha256(expected_material).hexdigest()
        windows = proposal.coordinates.template == 'Windows Machine'
        mapped=proposal.name.startswith('mcp-v4-target-job-mapped-')
        service=proposal.name.startswith('mcp-v4-target-svc-')
        reference=proposal.name.startswith('mcp-v4-target-svc-ref-')
        compiler=compile_service_account_reference_target_request if reference else compile_service_account_target_request if service else compile_job_mapped_target_request if mapped else compile_windows_execution_target_request if windows else compile_request
        compiled = compiler(proposal, expected_material)
        if not hmac.compare_digest(body, compiled):
            raise ValueError
        return _digest((SERVICE_ACCOUNT_REFERENCE_CONTRACT if reference else SERVICE_ACCOUNT_CONTRACT if service else JOB_MAPPED_CONTRACT if mapped else WINDOWS_EXECUTION_CONTRACT if windows else CONTRACT, proposal.state_digest,
                        hashlib.sha256(body).hexdigest(), material_digest))
    finally:
        _zeroize_mutable(compiled)
        if isinstance(expected_material, bytearray):
            _zeroize_mutable(expected_material)


def _snapshot(state: c.TargetState) -> dict[str, object]:
    return {'name':state.name,'serial_digest':state.serial_digest,
        'coordinates':[getattr(state.coordinates,key) for key in c._COORDINATES],
        'field_digests':state.field_digests,'metadata_digests':state.metadata_digests,
        'state_digest':state.state_digest,'preserved_digest':state.preserved_digest}


def _state(value: Any) -> c.TargetState:
    if type(value) is not dict or set(value) != {'name','serial_digest','coordinates','field_digests','metadata_digests','state_digest','preserved_digest'}:
        raise ValueError
    if type(value['coordinates']) is not list or len(value['coordinates']) != 4:
        raise ValueError
    result = c.TargetState(value['name'],value['serial_digest'],c.TargetCoordinates(*value['coordinates']),
        tuple(tuple(item) for item in value['field_digests']),tuple(tuple(item) for item in value['metadata_digests']),
        value['state_digest'],value['preserved_digest'])
    c._checked_state(result)
    return result


class TargetCreationHttpTransport(_TargetOperationRecords):
    __slots__ = ('_config','_proposal','_body','_body_digest','_key','_directory','_identity','_namespace',
        '_enabled','_recovery_enabled','_clock','_last_clock','_clock_failed','_factory','_context','_path','_source_context_digest',
        '_owner_read_source','_owner_read_context')
    _config: SecretMetadataHttpTransportConfig
    _proposal: c.TargetState
    _body: bytearray
    _body_digest: str
    _key: bytes
    _enabled: bool
    _recovery_enabled: bool
    _factory: Callable[..., _Connection]
    _context: ssl.SSLContext
    _path: str
    _source_context_digest: str | None
    _owner_read_source: WindowsTargetOwnerSource | None
    _owner_read_context: str | None

    def __init__(self, config: SecretMetadataHttpTransportConfig, proposal: c.TargetState, body: bytearray, *,
                 state_directory: Path, provenance_key: bytes, execution_enabled: bool = False,
                 recovery_enabled: bool = False,
                 expected_material: bytearray | None = None,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None,
                 owner_read_source: WindowsTargetOwnerSource | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(execution_enabled) is not bool
                    or type(recovery_enabled) is not bool
                    or type(provenance_key) is not bytes or not 32 <= len(provenance_key) <= 4096): raise ValueError
            config.__post_init__(); c._checked_state(proposal)
            # The service prerequisite has unresolved native duplicate failures.
            # Retain its compilers and read-only custody, but do not dispatch it.
            if proposal.name.startswith('mcp-v4-target-svc-') and (execution_enabled or recovery_enabled):raise ValueError
            serialization = _verify_request(body, proposal, expected_material)
            url = urlsplit(config.base_url)
            if not url.hostname or url.username is not None or url.password is not None: raise ValueError
            if proposal.name in ('.','..') or any(char in proposal.name for char in '/\\?#'): raise ValueError
            if (not isinstance(state_directory,Path) or not state_directory.is_absolute()
                    or '..' in state_directory.parts or any(p.is_symlink() for p in (state_directory,*state_directory.parents))): raise ValueError
            info = state_directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError
            identity = (info.st_dev,info.st_ino)
            ca_digest = None
            if config.ca_file is None: context = _ssl_context(config)
            else:
                with Path(config.ca_file).open('rb') as stream: ca = stream.read(1048577)
                if not 0 < len(ca) <= 1048576: raise ValueError
                ca_digest = hashlib.sha256(ca).hexdigest()
                context = ssl.create_default_context(cadata=ca.decode('ascii'))
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED: raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            body_digest = hashlib.sha256(body).hexdigest()
            owner_context = None
            if owner_read_source is not None:
                if type(owner_read_source) is not WindowsTargetOwnerSource or proposal.coordinates.template != 'Windows Machine':
                    raise ValueError
                owner_context = owner_read_source.check_binding(config, target_name=proposal.name,
                    serial_digest=proposal.serial_digest)
                owner_read_source.check_request(body)
            namespace = _digest((_CONTRACT,proposal.state_digest,body_digest,config.base_url,
                hashlib.sha256(config.bearer_token.encode()).hexdigest(),ca_digest,
                hashlib.sha256(provenance_key).hexdigest(),str(state_directory),identity,
                *(() if serialization is None else (serialization,)),
                *(() if owner_context is None else (owner_context,))))
            for key,value in {'_config':config,'_proposal':proposal,'_body_digest':body_digest,
                    '_key':provenance_key,'_directory':state_directory,'_identity':identity,'_namespace':namespace,
                    '_enabled':execution_enabled,'_recovery_enabled':recovery_enabled,'_clock':clock or (lambda:int(time.time())),
                    '_last_clock':None,'_clock_failed':False,'_factory':connection_factory or http.client.HTTPSConnection,
                    '_owner_read_source':owner_read_source,'_owner_read_context':owner_context,
                    '_source_context_digest':None if ca_digest is None else c._api_source_context(
                        config.base_url,hashlib.sha256(config.bearer_token.encode()).hexdigest(),
                        ca_digest,proposal.serial_digest),
                    '_context':context,'_path':_PATH+'/'+quote(proposal.name,safe='')+'?with_meta=true&vdom=root'}.items():
                object.__setattr__(self,key,value)
            object.__setattr__(self,'_body',bytearray(body))
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None
        finally:
            if isinstance(body,bytearray): _zeroize_mutable(body)
            if isinstance(expected_material,bytearray): _zeroize_mutable(expected_material)

    def close(self) -> None:
        self._enabled = False
        self._recovery_enabled = False
        _zeroize_mutable(self._body)

    def _exchange(self, method: Literal['GET','POST','DELETE'], *, absent: bool = False,
                  deadline: int, guard: Callable[[],None],
                  on_response: Callable[[Any],None] | None = None,
                  on_failure: Callable[[bytearray,int],None] | None = None) -> bytearray:
        if method == 'GET' and not absent and self._owner_read_source is not None:
            if self._owner_read_context != self._owner_read_source.check_binding(self._config,
                    target_name=self._proposal.name, serial_digest=self._proposal.serial_digest):
                raise TargetCreationTransportError(_ERROR)
            return self._owner_read_source.read(expires_at=deadline, before_send=guard)
        raw = bytearray(_LIMIT+1)
        response = connection = view = active_socket = None
        transfer = False
        def check_deadline(*, refresh: bool = False) -> float:
            remaining = deadline-self._now()
            if remaining <= 0: raise ValueError
            timeout = min(self._config.timeout_seconds, remaining)
            if refresh and active_socket is not None and active_socket.fileno() >= 0:
                active_socket.settimeout(timeout)
            return timeout
        try:
            try:
                timeout = check_deadline()
                context = self._context
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED: raise ValueError
                url = urlsplit(self._config.base_url)
                connection = self._factory(url.hostname,url.port or 443,timeout=timeout,context=context)
                guard(); setattr(connection, 'timeout', check_deadline()); connection.connect()
                active_socket = getattr(connection, 'sock', None)
                guard(); check_deadline(refresh=True)
                if method == 'POST': view = memoryview(self._body).toreadonly()
                connection.request(method,_PATH+'?vdom=root' if method == 'POST' else self._path,view,
                    {'Authorization':'Bearer '+self._config.bearer_token,'Accept':'application/json',
                     'Content-Type':'application/json','Accept-Encoding':'identity','Connection':'close',
                     'Cache-Control':'no-store','User-Agent':'fortipam-mcp-target-lifecycle/1'})
                check_deadline(refresh=True)
                response = connection.getresponse()
                if on_response is not None:
                    on_response(response)
                check_deadline()
                expected_status=response.status == (404 if absent else 200)
                if (not expected_status and on_failure is None or 'json' not in response.getheader('Content-Type','').lower()
                        or response.getheader('Content-Encoding','identity') not in ('','identity')): raise ValueError
                limit=_LIMIT if expected_status else min(_LIMIT,16384)
                used = 0
                while used <= limit:
                    check_deadline(refresh=True)
                    with memoryview(raw)[used:limit+1] as buffer: count = response.readinto(buffer)
                    check_deadline()
                    if type(count) is not int or count < 0 or used+count > limit: raise ValueError
                    if not count: break
                    used += count
                raw = _take_mutable_prefix(raw, used)
                if not expected_status:
                    if on_failure is not None:on_failure(raw,response.status)
                    raise ValueError
            finally:
                if view is not None: view.release()
                for resource in (response,connection):
                    if resource is not None:
                        try: resource.close()
                        except Exception: pass
            check_deadline()
            transfer = True
            return raw
        finally:
            if not transfer: _zeroize_mutable(raw)

    def _observe_native_response(self, directory: int, phase: str, claim: dict[str, Any], response: Any) -> None:
        """Seal only minimal header observations; never qualify a success ACK."""
        if phase not in ('create','delete') or self._read(directory,phase+'.claim.json') != claim:
            raise ValueError
        status = response.status
        mime = response.getheader('Content-Type','')
        encoding = response.getheader('Content-Encoding','identity')
        value = {'contract':'fortipam-target-native-response-observation-v1', 'namespace':self._namespace,
            'claim_digest':_digest(claim), 'phase':phase,
            'http_status':status if type(status) is int and 100 <= status <= 599 else None,
            'json_content_type':type(mime) is str and 'json' in mime.lower(),
            'identity_encoding':type(encoding) is str and encoding in ('','identity'),
            'success_ack_qualified':False, 'raw_response_stored':False}
        value['seal'] = hmac.new(self._key,_DOMAIN+b'header-observation\x00'+_canonical(value),hashlib.sha256).hexdigest()
        self._write(directory,phase+'.response.json',value)

    def _observe_native_failure(self, directory: int, phase: str, claim: dict[str, Any], raw: bytearray, status: int) -> None:
        """Keep only an original error code/categories, never an ACK or raw text."""
        if phase not in ('create','delete') or self._read(directory,phase+'.claim.json') != claim:raise ValueError
        value: dict[str,Any]={'contract':'fortipam-target-native-failure-observation-v1','namespace':self._namespace,
            'claim_digest':_digest(claim),'phase':phase,'http_status':status,'envelope_verified':False,
            'native_error_code':None,'message_mentions':{},'success_ack_qualified':False,'raw_response_stored':False}
        text=bytearray()
        try:
            start=_skip_json_space(raw,0);end=_json_value_end(raw,start)
            if _skip_json_space(raw,end)!=len(raw):raise ValueError
            fields=m._object_spans(raw,start,end,frozenset({'serial','version','build','http_status','http_method',
                'path','name','vdom','status','error','cli_error','message'}))
            for key,wanted in {'version':'v7.0.0','build':29,'http_status':status,
                    'http_method':'POST' if phase=='create' else 'DELETE','path':'secret','name':'target','vdom':'root'}.items():
                actual=m._scalar(raw,fields[key])
                if type(actual)is not type(wanted) or actual!=wanted:raise ValueError
            serial=m._scalar(raw,fields['serial'])
            if type(serial)is not str or hashlib.sha256(serial.encode()).hexdigest()!=self._proposal.serial_digest:raise ValueError
            if m._scalar(raw,fields['status'])!='error':raise ValueError
            code=m._scalar(raw,fields['error'])
            if type(code)is not int:raise ValueError
            value.update(envelope_verified=True,native_error_code=code)
            for key in ('cli_error','message'):
                if key in fields and raw[fields[key][0]]==34:
                    text.extend(memoryview(raw)[slice(*fields[key])])
            lower=bytearray(text.lower())
            try:
                value['message_mentions']={name:term in lower for name,term in (
                    ('duplicate',b'duplicate'),('already_exists',b'already exists'),('not_found',b'not found'),
                    ('template',b'template'),('permission',b'permission'),('license',b'license'),('limit',b'limit'),('invalid',b'invalid'))}
            finally:_zeroize_mutable(lower)
        except (ValueError,KeyError,IndexError):
            pass
        finally:_zeroize_mutable(text)
        value['seal']=hmac.new(self._key,_DOMAIN+b'native-failure-observation\x00'+_canonical(value),hashlib.sha256).hexdigest()
        self._write(directory,phase+'.failure.json',value)

    def read_current(self, *, expires_at: int, before_send: Callable[[], None]) -> c.TargetState:
        """Read the fixed full Target state without claiming a lifecycle phase.

        Return an actual observation, not the proposal, baseline or retained
        mutation receipt. The trusted caller supplies fresh dependency checks;
        this read grants no ownership or write authority.
        """
        content = bytearray()
        try:
            now = self._now()
            if (not callable(before_send) or type(expires_at) is not int
                    or not 0 < expires_at-now <= 60):
                raise ValueError
            def guard() -> None:
                if not now <= self._now() < expires_at: raise ValueError
                before_send()
                if not now <= self._now() < expires_at: raise ValueError
            content = self._exchange('GET',deadline=expires_at,guard=guard)
            current = c.capture_target_state(content,expected_name=self._proposal.name,
                expected_serial_digest=self._proposal.serial_digest)
            guard()
            return current
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None
        finally:
            _zeroize_mutable(content)

    def read_absence(self, *, expires_at: int, before_send: Callable[[], None]) -> str:
        """Qualify a fresh fixed-route 404 and return a semantic absence digest.

        This is only actor-visible absence. The caller must separately prove
        global namespace absence before creation. No phase claim is consumed.
        """
        content = bytearray()
        try:
            now = self._now()
            if (not callable(before_send) or type(expires_at) is not int
                    or not 0 < expires_at-now <= 60):
                raise ValueError
            def guard() -> None:
                if not now <= self._now() < expires_at: raise ValueError
                before_send()
                if not now <= self._now() < expires_at: raise ValueError
            content = self._exchange('GET', absent=True, deadline=expires_at, guard=guard)
            e._envelope(content, self._proposal, absent=True)
            guard()
            return c._digest(('target-actor-visible-absence-v1', self._proposal.name,
                              self._proposal.serial_digest))
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None
        finally:
            _zeroize_mutable(content)

    def create(self, *, plan_digest: str, authorization_digest: str, expires_at: int,
               before_send: Callable[[],None]) -> e.TargetCreationEvidence:
        buffers: list[bytearray] = []
        try:
            if not self._enabled or not callable(before_send): raise ValueError
            e._require_digest(plan_digest); e._require_digest(authorization_digest)
            now = self._now()
            if type(expires_at) is not int or not 0 < expires_at-now <= 60: raise ValueError
            with self._lock() as directory:
                before_send()
                claim = {'namespace':self._namespace,'plan_digest':plan_digest,'authorization_digest':authorization_digest,
                    'body_digest':self._body_digest,'claimed_at':now,'expires_at':expires_at}
                self._write(directory,'create.claim.json',claim)
                def guard() -> None:
                    info = self._directory.lstat()
                    if ((info.st_dev,info.st_ino) != self._identity or not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                            or not now <= self._now() < expires_at
                            or self._read(directory,'create.claim.json') != claim
                            or hashlib.sha256(self._body).hexdigest() != self._body_digest): raise ValueError
                    before_send()
                    if not now <= self._now() < expires_at: raise ValueError
                absence = self._exchange('GET',absent=True,deadline=expires_at,guard=guard); buffers.append(absence)
                absent_digest = e._envelope(absence,self._proposal,absent=True)
                self._write(directory,'create.absent.json',{'namespace':self._namespace,
                    'claim_digest':_digest(claim),'absence_digest':absent_digest})
                acknowledgement = self._exchange('POST',deadline=expires_at,guard=guard,
                    on_response=lambda response:self._observe_native_response(directory,'create',claim,response),
                    on_failure=lambda raw,status:self._observe_native_failure(directory,'create',claim,raw,status))
                buffers.append(acknowledgement)
                ack_digest = e._envelope(acknowledgement,self._proposal,absent=False)
                self._write(directory,'create.ack.json',{'namespace':self._namespace,
                    'claim_digest':_digest(claim),'acknowledgement_digest':ack_digest})
                detail = self._exchange('GET',deadline=expires_at,guard=guard); buffers.append(detail)
                evidence = e.verify_target_creation_evidence(absence,acknowledgement,detail,
                    proposal=self._proposal,claim_digest=_digest(claim))
                guard()
                value = {'namespace':self._namespace,'proposal_digest':evidence.proposal_digest,
                    'claim_digest':evidence.claim_digest,'absence_digest':evidence.absence_digest,
                    'acknowledgement_digest':evidence.acknowledgement_digest,'created':_snapshot(evidence.created),
                    'evidence_digest':evidence.evidence_digest,'anchors':{name:_digest(self._read(directory,name))
                        for name in ('create.claim.json','create.absent.json','create.ack.json')}}
                value['seal'] = hmac.new(self._key,_DOMAIN+_canonical(value),hashlib.sha256).hexdigest()
                self._write(directory,'create.verified.json',value)
                return evidence
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None
        finally:
            for content in buffers: _zeroize_mutable(content)
            self.close()

    def _load_creation_evidence(self, directory: int) -> e.TargetCreationEvidence:
        value = self._read(directory,'create.verified.json')
        seal = value.pop('seal'); e._require_digest(seal)
        if not hmac.compare_digest(seal,hmac.new(self._key,_DOMAIN+_canonical(value),hashlib.sha256).hexdigest()): raise ValueError
        anchors = {name:_digest(self._read(directory,name)) for name in ('create.claim.json','create.absent.json','create.ack.json')}
        if value['anchors'] != anchors or value['proposal_digest'] != self._proposal.state_digest: raise ValueError
        created = _state(value['created'])
        result = e.TargetCreationEvidence(value['proposal_digest'],value['claim_digest'],value['absence_digest'],
            value['acknowledgement_digest'],created,value['evidence_digest'])
        if (result.claim_digest != anchors['create.claim.json'] or result.evidence_digest != e._fingerprint(
            result.proposal_digest,result.claim_digest,result.absence_digest,result.acknowledgement_digest,created)): raise ValueError
        return result

    def load_creation_evidence(self) -> e.TargetCreationEvidence:
        """Authenticate original local records; this alone does not authorize a mutation."""
        try:
            with self._lock() as directory:
                return self._load_creation_evidence(directory)
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None

    def recover(self, *, expected_current: c.TargetState, plan_digest: str,
                authorization_digest: str, expires_at: int, before_send: Callable[[],None],
                reference_count: Callable[[str],int],
                creation_evidence_digest: str | None = None,
                owner_recovery: WindowsTargetOwnerRecovery | None = None) -> None:
        """One independently authorized original-ACK cleanup; never adopt or retry.

        The trusted caller supplies a current-state-bound M4 guard and fixed
        same-device reference reader. Original non-coordinate state must remain
        intact, allowing explicit cleanup of an owned coordinate-change failure.
        A supplied creation_evidence_digest pins the original seal under this
        operation lock, avoiding reentrant ownership reads from external guards.
        """
        buffers: list[bytearray] = []
        try:
            if not self._recovery_enabled or not callable(before_send) or not callable(reference_count): raise ValueError
            c._checked_state(expected_current)
            e._require_digest(plan_digest); e._require_digest(authorization_digest)
            now = self._now()
            if type(expires_at) is not int or not 0 < expires_at-now <= 60: raise ValueError
            with self._lock() as directory:
                evidence = self._load_creation_evidence(directory)
                if creation_evidence_digest is not None:
                    e._require_digest(creation_evidence_digest)
                    if evidence.evidence_digest != creation_evidence_digest: raise ValueError
                if (expected_current.name != evidence.created.name
                        or expected_current.serial_digest != evidence.created.serial_digest
                        or expected_current.preserved_digest != evidence.created.preserved_digest): raise ValueError
                if self._owner_read_source is not None:
                    from .windows_target_owner_recovery import WindowsTargetOwnerRecovery
                    if type(owner_recovery) is not WindowsTargetOwnerRecovery:
                        raise ValueError
                    if not owner_recovery._enabled:
                        raise ValueError
                    owner_recovery.check_binding(self, evidence, expected_current)
                elif owner_recovery is not None:
                    raise ValueError
                before_send()
                claim = {'namespace':self._namespace,'plan_digest':plan_digest,'authorization_digest':authorization_digest,
                    'creation_evidence_digest':evidence.evidence_digest,'current_digest':expected_current.state_digest,
                    'claimed_at':now,'expires_at':expires_at}
                self._write(directory,'delete.claim.json',claim)
                def guard() -> None:
                    info = self._directory.lstat()
                    if ((info.st_dev,info.st_ino) != self._identity or not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                            or not now <= self._now() < expires_at
                            or self._read(directory,'delete.claim.json') != claim
                            or self._load_creation_evidence(directory) != evidence): raise ValueError
                    before_send()
                    if not now <= self._now() < expires_at: raise ValueError
                def delete_guard() -> None:
                    guard()
                    count = reference_count(evidence.created.name)
                    if type(count) is not int or count != 0: raise ValueError
                    if owner_recovery is None:
                        content = self._exchange('GET',deadline=expires_at,guard=guard);buffers.append(content)
                        current = c.capture_target_state(content,expected_name=evidence.created.name,
                            expected_serial_digest=evidence.created.serial_digest)
                    else:
                        current = owner_recovery.read_current_for_dispatch(expires_at=expires_at,before_send=guard)
                    if current.state_digest != expected_current.state_digest: raise ValueError
                    guard()
                if owner_recovery is None:
                    acknowledgement = self._exchange('DELETE',deadline=expires_at,guard=delete_guard,
                        on_response=lambda response:self._observe_native_response(directory,'delete',claim,response),
                        on_failure=lambda raw,status:self._observe_native_failure(directory,'delete',claim,raw,status))
                else:
                    acknowledgement = owner_recovery.dispatch(directory=directory, claim=claim, expires_at=expires_at,
                        before_read=guard, before_delete=delete_guard)
                buffers.append(acknowledgement)
                ack_digest = e._envelope(acknowledgement,self._proposal,absent=False,method='DELETE')
                ack = {'namespace':self._namespace,'claim_digest':_digest(claim),'acknowledgement_digest':ack_digest}
                self._write(directory,'delete.ack.json',ack)
                owner_absence_digest = None
                if owner_recovery is None:
                    absence = self._exchange('GET',absent=True,deadline=expires_at,guard=guard)
                else:
                    absence, owner_absence_digest = owner_recovery.observe_absence(expires_at=expires_at,before_send=guard)
                buffers.append(absence)
                absent_digest = e._envelope(absence,self._proposal,absent=True)
                guard()
                value = {'namespace':self._namespace,'claim_digest':_digest(claim),'ack_digest':_digest(ack),
                    'creation_evidence_digest':evidence.evidence_digest,'absence_digest':absent_digest}
                if owner_absence_digest is not None:
                    value['owner_global_absence_digest'] = owner_absence_digest
                value['seal'] = hmac.new(self._key,_DOMAIN+b'delete\x00'+_canonical(value),hashlib.sha256).hexdigest()
                self._write(directory,'delete.verified.json',value)
        except Exception:
            raise TargetCreationTransportError(_ERROR) from None
        finally:
            for content in buffers: _zeroize_mutable(content)
            self.close()
