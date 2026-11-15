"""One in-call next-password login under the distinct owned reset v2 M4.

No runtime registration, selectors, credential return, retries or binding
promotion. Original configuration custody remains unchanged after audit rows.
"""
from __future__ import annotations

from collections.abc import Callable
from time import sleep
from typing import Any
from urllib.parse import urlsplit

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .local_user_reset_fixture_preflight import _ACTOR,_actor_context
from .local_user_reset_http_transport import _dispose_password,_valid_password
from .local_user_reset_login_acceptance import _exchange,_LOGIN_SETTLE_SECONDS
from .local_user_reset_owner_session import _AUTH,_LOGIN,_LoginForm
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import SYSTEM_STATUS_PATH,_ssl_context,_zeroize_mutable

_ERROR="The private original-owned new-password acceptance is unavailable."


class LocalResetOwnedLogin(_OpaqueC3Object):
    def __init__(self,adapter: Any,*,client_factory: Callable[...,Any]=httpx.Client) -> None:
        from .local_user_reset_owned_adapter import LocalResetOwnedAdapter
        if (type(adapter) is not LocalResetOwnedAdapter or not adapter._material._verify_login
                or not callable(client_factory)):raise ValueError(_ERROR)
        self._adapter,self._factory=adapter,client_factory
        self._client: Any=None;self._consumed=False;self._resources_closed=True

    def _identity(self,raw: bytearray,*,actor: bool) -> None:
        a=self._adapter;fields=_object_spans(raw,0,len(raw))
        if m._scalar(raw,fields["serial"])!=a._sources._serial:raise ValueError
        if actor:
            _actor_context(raw,expected_name=a._sources._state._draft.username)
        else:
            if (m._scalar(raw,fields["version"]) not in ("7.0.0","v7.0.0")
                    or m._scalar(raw,fields["build"])!=29):raise ValueError

    def run(self) -> dict[str,Any]:
        a=self._adapter;content=bytearray();view=None;result: dict[str,Any]=dict(
            login_post_attempted=False,login_verified=False,logout_verified=False,resources_closed=True)
        try:
            if self._consumed:raise ValueError
            self._consumed=True;a._guard();a._material.check_staged()
            if a._owner is None or not a._owner.logout_verified or a._owner._client is not None:raise ValueError
            sleep(_LOGIN_SETTLE_SECONDS);a._guard()
            self._resources_closed=False
            self._client=self._factory(base_url=a._sources._config.base_url,verify=_ssl_context(a._sources._config),
                timeout=a._sources._config.timeout_seconds,follow_redirects=False,trust_env=False,
                headers={"Accept-Encoding":"identity","User-Agent":"fortipam-original-owned-login/v2"})
            def exchange(method: str,path: str,*,data: dict[str,str]|None=None,json_body: bool=False) -> tuple[int,str|None,bytearray]:
                a._guard()
                remaining=a._authorization.expires_at-a._authority._now()
                if remaining<=0:raise ValueError
                self._client.timeout=min(a._sources._config.timeout_seconds,remaining)
                return _exchange(self._client,method,path,data=data,require_json=json_body)
            status,_,content=exchange("GET",_LOGIN)
            form=_LoginForm();form.feed(content.decode("utf-8"));_zeroize_mutable(content)
            if status!=200 or form.matches!=1:raise ValueError
            view=a._material.acquire_login(a)
            if not _valid_password(view) or not 32<=view.nbytes<=128:raise ValueError
            a._guard();a._write("login-send.json",dict(change_ack_digest=canonical_digest(a._record("change-ack.json")),
                sent_at=a._authority._now()))
            result["login_post_attempted"]=True
            data=dict(username=a._sources._state._draft.username,password=view.tobytes().decode("utf-8"),
                magic="0",**{"4Tredir":"/","4Tmthd":"0"})
            try:status,location,content=exchange("POST",_AUTH,data=data)
            finally:
                data.clear();_dispose_password(view);view=None
            _zeroize_mutable(content);redirect=urlsplit(location or "")
            if (status!=303 or not location or len(location)>2048 or redirect.scheme or redirect.netloc or redirect.fragment
                    or not redirect.path.startswith("/") or redirect.path.startswith("//") or "%" in redirect.path
                    or "\\" in redirect.path or any(ord(c)<33 or ord(c)>126 for c in location)
                    or redirect.path=="/api" or redirect.path.startswith("/api/") or redirect.path in {_AUTH,"/logout","/remote/login"}):raise ValueError
            _,_,content=exchange("GET",location);_zeroize_mutable(content)
            status,_,content=exchange("GET",SYSTEM_STATUS_PATH,json_body=True)
            if status!=200:raise ValueError
            self._identity(content,actor=False);_zeroize_mutable(content)
            status,_,content=exchange("GET",_ACTOR,json_body=True)
            if status!=200:raise ValueError
            self._identity(content,actor=True);_zeroize_mutable(content)
            result["login_verified"]=True
        except Exception:pass
        finally:
            _zeroize_mutable(content)
            if view is not None:_dispose_password(view)
            if self._client is not None:
                if result["login_post_attempted"]:
                    try:
                        # Cleanup is attempted even when the action deadline has
                        # elapsed. No new login or privileged write is possible.
                        status,_,content=_exchange(self._client,"GET","/logout");_zeroize_mutable(content)
                        denied,_,content=_exchange(self._client,"GET",SYSTEM_STATUS_PATH);_zeroize_mutable(content)
                        result["logout_verified"]=status==200 and denied in {401,403}
                    except Exception:pass
                clean=True
                for cleanup in (self._client.cookies.clear,self._client.close):
                    try:cleanup()
                    except Exception:clean=False
                self._resources_closed=clean and getattr(self._client,"is_closed",False) is True
                if self._resources_closed:self._client=None
            _zeroize_mutable(content);result["resources_closed"]=self._resources_closed
            try:
                send=a._record("login-send.json")
                a._write("login-result.json",dict(**result,send_digest=canonical_digest(send),finished_at=a._authority._now()))
            except Exception:pass
        return result

    def close(self) -> None:
        """Close only retained local resources; never repeat authentication."""
        if self._client is not None:
            clean=True
            for cleanup in (self._client.cookies.clear,self._client.close):
                try:cleanup()
                except Exception:clean=False
            self._resources_closed=clean and getattr(self._client,"is_closed",False) is True
            if self._resources_closed:self._client=None
