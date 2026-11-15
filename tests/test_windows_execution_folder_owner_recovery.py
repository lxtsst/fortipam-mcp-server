"""New Owner recovery does not widen Archive scope or accept a non-M4 delete."""
import pytest

from fortipam_mcp.folder_archive_owner_session import FixedFolderArchiveOwnerSession, FolderArchiveOwnerSessionError
from fortipam_mcp.folder_http_transport import FolderTransportConfig
from fortipam_mcp.windows_execution_folder_owner_recovery import WindowsFolderOwnerRecoverySession
from test_windows_execution_folder_lifecycle import make, Native, lifecycle


def test_new_name_uses_its_own_validated_profile_and_requires_active_original_m4(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api);create,_,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview());assert str(create.execute().outcome)=='succeeded'
    original=create.original_creation();create.close()
    recover,store,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    issued=recover.issue(recover.preview())
    config=policy._config
    with pytest.raises(FolderArchiveOwnerSessionError):
        FixedFolderArchiveOwnerSession(FolderTransportConfig(config.base_url,config.bearer_token,30,None,explicitly_enabled=True),
            owner_name=source._request.binding.owner_name,folder_name=source._request.binding.name,
            credentials=policy._credentials,client_factory=api.base.factory)
    owner=WindowsFolderOwnerRecoverySession(source,original,plan=issued.plan,authorization=issued.authorization,
        store=store,client_factory=api.base.factory)
    owner.read_collection();owner.inspect(source._request.binding.owner_name)
    with pytest.raises(FolderArchiveOwnerSessionError):owner.delete_empty_folder(41)
    with pytest.raises(FolderArchiveOwnerSessionError):
        owner.delete_empty_folder_original(41,before_dispatch=lambda:None,observe_response=lambda *args:None,
            consume_original_ack=lambda *args:None)
    assert native.calls==[('POST','/api/v2/cmdb/secret/folder')] and store.claim_count==0
    recover.close();source.close();policy.close()
