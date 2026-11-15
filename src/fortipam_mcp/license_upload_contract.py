"""Private build29 frontend request encoding; no upload, ACK or install authority."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json

from v4_planning.material_provider import MaterialAccessDenied
from .license_artifact_source import LicenseArtifactSource
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT='fortipam-build29-license-upload-request-local/v1'
REQUEST_SOURCE_SHA256='841c2d7595337b59a665f6cd011590160fdc74488e4f4bdc26d2a2f478a9c4ae'
UPLOAD_PATH='/api/v2/monitor/system/vmlicense/upload'
_ERROR='The private license upload request is unavailable.'
_B64=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


@contextmanager
def _compile_license_upload(source: LicenseArtifactSource,*,scope_digest: str,audience_digest: str) -> Iterator[memoryview]:
    """Borrow the original file once; lend only a temporary private JSON view.

    Filename comes from that file, never an MCP argument. Base64 is written
    directly into the owned mutable body, without creating a material string.
    This codec supplies no native format, entitlement, dispatch or recovery proof.
    """
    body=bytearray(); view=None
    try:
        if type(source) is not LicenseArtifactSource: raise ValueError
        with source._lock:
            path=source._path; filename=path.name
            # A local filesystem profile, not an upstream filename constraint.
            if (not filename or len(filename.encode('utf-8'))>255
                    or any(ord(char)<32 or ord(char)==127 for char in filename)): raise ValueError
            name=json.dumps(filename,ensure_ascii=False,separators=(',',':')).encode('utf-8')
            with source._borrow_once(scope_digest=scope_digest,audience_digest=audience_digest) as raw:
                if source._path is not path: raise ValueError
                body.extend(b'{"filename":'); body.extend(name); body.extend(b',"file_content":"')
                # Finish all allocation before writing any encoded material.
                offset=len(body); body.extend(bytearray(4*((len(raw)+2)//3)+2))
                body[-2]=34; body[-1]=125
                for index in range(0,len(raw),3):
                    remaining=len(raw)-index
                    first=raw[index]; second=raw[index+1] if remaining>1 else 0
                    third=raw[index+2] if remaining>2 else 0
                    body[offset]=_B64[first>>2]
                    body[offset+1]=_B64[((first&3)<<4)|(second>>4)]
                    body[offset+2]=_B64[((second&15)<<2)|(third>>6)] if remaining>1 else 61
                    body[offset+3]=_B64[third&63] if remaining>2 else 61
                    offset+=4
                source._current()
                if source._path is not path: raise ValueError
                view=memoryview(body).toreadonly()
                try:
                    yield view
                    if source._path is not path: raise ValueError
                finally:
                    view.release(); view=None
    except Exception: raise MaterialAccessDenied(_ERROR) from None
    finally:
        try:
            if view is not None: view.release()
        finally:
            _zeroize_mutable(body)


def license_upload_request_boundary() -> dict[str,object]:
    """Source facts only; never include file names, hashes or encoded material."""
    return dict(contract=CONTRACT,request_source_sha256=REQUEST_SOURCE_SHA256,
        source_kind='build29_frontend_serialization',method='POST',path=UPLOAD_PATH,
        json_fields=['filename','file_content'],file_content_encoding='standard_base64',
        filename_from_original_private_file=True,license_material_in_mcp=False,
        native_license_format_verified=False,entitlement_verified=False,
        native_request_accepted=False,strict_ack_contract_verified=False,
        ui_non_error_status_is_not_strict_ack=True,
        valid_license_ui_branch_downloads_global_configuration_backup=True,
        backup_custody_and_independent_recovery_required=True,
        maintenance_and_reboot_qualification_required=True,
        post_boot_license_and_capacity_readback_required=True,
        source_or_request_grants_authority=False,execution_authorized=False,
        http_transport_registered=False,device_contacted=False)
