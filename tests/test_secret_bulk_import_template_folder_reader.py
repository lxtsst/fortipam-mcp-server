"""One bounded, stable visible template/folder read window; no catalog grants."""

import copy
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import secret_bulk_import_reference_reader as reader
from test_secret_bulk_import_metadata import MATERIAL, SERIAL_DIGEST, response


@pytest.mark.parametrize("fault", [None, "order", "template-drift", "folder-drift", "revision-drift",
    "missing-count", "wrong-count", "wrong-kind", "missing-parent", "cycle", "device",
    "decode-deadline", "path-deadline", "close-deadline", "rollback", "response-close"])
def test_six_read_window_and_failure_cleanup(tmp_path, monkeypatch, caplog, fault):
    calls, clients, streams, buffers = [], [], [], []
    clock = [10.0]

    class Stream(httpx.SyncByteStream):
        def __init__(self, raw):
            self.raw, self.closed = raw, False
            streams.append(self)

        def __iter__(self):
            if fault == "rollback":
                clock[0] -= 1
            yield self.raw

        def close(self):
            self.closed = True
            if fault == "response-close":
                raise RuntimeError("SYNTHETIC_PRIVATE_CLOSE_FAILURE")

    def handle(request):
        calls.append(request)
        index = (len(calls) - 1) % 3
        table = "template" if index == 0 else "folder"
        assert request.method == "POST"
        assert request.url.path == "/api/v2/cmdb/secret/" + table
        assert request.url.query == ((
            "format=name%7Cfield%7Cpermissions" if index == 0 else
            "format=id%7Cname%7Cparent-folder%7Cfolder-type%7Cpermissions")
            + "&with_meta=true&vdom=root").encode()
        assert request.content == (reader._PERSONAL_BODY if index == 2 else b'{"json_filter":[]}')
        assert request.headers["x-http-method-override"] == "GET"
        assert request.headers["authorization"] == "Bearer SYNTHETIC_PRIVATE_TOKEN"
        assert "cookie" not in request.headers
        assert request.headers["accept-encoding"] == "identity"
        data = response(table)
        row = data["results"][0]
        if index == 0:
            second = {**row, "name": "Second template"}
            data["results"].append(second)
            if fault == "template-drift" and len(calls) == 4:
                row["permissions"] = {"user": "none"}
        elif index == 1:
            row.update(name="Public", permissions={"user": "view"})
            child = {**row, "id": 10, "name": "Child", "parent-folder": 7}
            data["results"].append(child)
            if fault == "missing-parent":
                child["parent-folder"] = 999
            elif fault == "cycle":
                row["parent-folder"] = 10
        else:
            row.update(id=8, name="Personal", **{"folder-type": "personal"})
            if fault == "wrong-kind":
                row["folder-type"] = "public"
            if fault == "folder-drift" and len(calls) == 6:
                row["permissions"] = {"user": "view"}
        if index:
            data.update(filtered_count=len(data["results"]), size=27)
            if fault == "missing-count":
                del data["filtered_count"]
            elif fault == "wrong-count":
                data["filtered_count"] += 1
        if fault == "order" and len(calls) > 3:
            data["results"].reverse()
        if fault == "revision-drift" and len(calls) == 5:
            data["revision"] = "different"
        if fault == "device":
            data["serial"] = "other-synthetic-device"
        return httpx.Response(200, headers={"content-type": "application/json", "set-cookie": "a=SYNTHETIC_COOKIE"},
                              stream=Stream(json.dumps(data).encode()))

    class Client(httpx.Client):
        def __exit__(self, *args):
            super().__exit__(*args)
            if fault == "close-deadline":
                clock[0] += 31

    def factory(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        assert kwargs["verify"].check_hostname and kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        client = Client(transport=httpx.MockTransport(handle), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(reader, "_ssl_context", lambda _: ssl.create_default_context())
    original_wipe = reader._zeroize_mutable

    def wipe(raw):
        buffers.append(raw)
        original_wipe(raw)

    monkeypatch.setattr(reader, "_zeroize_mutable", wipe)
    original_scalar = reader.m._scalar

    def scalar(raw, span):
        assert MATERIAL.encode() not in raw[slice(*span)]
        return original_scalar(raw, span)

    monkeypatch.setattr(reader.m, "_scalar", scalar)
    original_project = reader.m.project_native_import_metadata

    def project(*args, **kwargs):
        result = original_project(*args, **kwargs)
        if fault == "decode-deadline":
            clock[0] += 31
        return result

    monkeypatch.setattr(reader.m, "project_native_import_metadata", project)
    original_paths = reader.d.project_import_folder_paths

    def paths(*args):
        result = original_paths(*args)
        if fault == "path-deadline":
            clock[0] += 31
        return result

    monkeypatch.setattr(reader.d, "project_import_folder_paths", paths)
    caplog.set_level(logging.DEBUG)
    config = reader.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "SYNTHETIC_PRIVATE_TOKEN", 30, None)
    if fault in (None, "order"):
        result = reader.read_import_template_folder_metadata(config, serial_digest=SERIAL_DIGEST,
                                                              client_factory=factory, clock=lambda: clock[0])
        assert len(calls) == 6 and len(result.templates) == 2 and len(result.folders) == 3
        assert result.public_folder_view.size == result.personal_folder_view.size == 27
        assert {folder.path: folder.can_add for folder in result.folders} == {
            "Public": False, "Public/Child": False, "Personal": True}
        assert result.observed_at == result.completed_at == 10
        assert not hasattr(result, "coverage") and not hasattr(result, "can_associate")
        assert "Synthetic" not in repr(result)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(RuntimeError):
                operation(result)
    else:
        with pytest.raises(reader.BulkImportReferenceReadError) as caught:
            reader.read_import_template_folder_metadata(config, serial_digest=SERIAL_DIGEST,
                                                        client_factory=factory, clock=lambda: clock[0])
        assert str(caught.value) == "Protected bulk-import reference read unavailable."
    assert len(calls) <= 6
    if fault == "decode-deadline":
        assert len(calls) == 1
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(stream.closed for stream in streams) and all(not any(raw) for raw in buffers)
    assert MATERIAL not in caplog.text and "SYNTHETIC_" not in caplog.text
    assert "synthetic.invalid" not in caplog.text
