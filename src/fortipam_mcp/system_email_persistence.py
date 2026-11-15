"""Private configuration/send ledgers bound to the existing durable Unix CAS.

No server startup, environment loader, key creation, new sidecar or authorization
issuer is supplied. Trusted composition must preserve the original state and
checkpoint namespaces; opening a ledger does not adopt receipts or replay slots.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .m4_checkpoint_client import UnixM4ExecutionCheckpoint
from .m4_execution_store import PersistentM4ExecutionStateStore
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from .system_email_delivery_m4_adapter import validate_delivery_store_separation

_ERROR = "The private system-email persistence binding is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class SystemEmailExecutionStoreSettings(_OpaqueC3Object):
    database_path: Path
    hmac_key_path: Path
    checkpoint: UnixPlanningCheckpointClientSettings
    checkpoint_store_ref: str

    def __post_init__(self) -> None:
        try:
            if (not isinstance(self.database_path, Path) or not self.database_path.is_absolute()
                    or not isinstance(self.hmac_key_path, Path) or not self.hmac_key_path.is_absolute()
                    or self.database_path == self.hmac_key_path
                    or type(self.checkpoint) is not UnixPlanningCheckpointClientSettings):
                raise ValueError
            require_ref(self.checkpoint_store_ref, 'system-email checkpoint store')
        except Exception:
            raise ValueError(_ERROR) from None


def open_system_email_execution_stores(configuration: SystemEmailExecutionStoreSettings,
        delivery: SystemEmailExecutionStoreSettings) -> tuple[PersistentM4ExecutionStateStore, PersistentM4ExecutionStateStore]:
    """Open two protected stores with no in-memory checkpoint substitution.

    Stores retain existing single-use history. Independent Authority backups and
    deployment access controls remain outside this same-process composition.
    """
    try:
        if (type(configuration) is not SystemEmailExecutionStoreSettings
                or type(delivery) is not SystemEmailExecutionStoreSettings
                or configuration.checkpoint_store_ref == delivery.checkpoint_store_ref):
            raise ValueError
        paths = (configuration.database_path, configuration.hmac_key_path,
                 delivery.database_path, delivery.hmac_key_path)
        if len({path.resolve() for path in paths}) != 4:
            raise ValueError
        checkpoints = [UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(item.checkpoint), item.checkpoint_store_ref)
                       for item in (configuration, delivery)]
        stores = tuple(PersistentM4ExecutionStateStore(item.database_path, item.hmac_key_path,
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=item.checkpoint_store_ref)
            for item, checkpoint in zip((configuration, delivery), checkpoints))
        validate_delivery_store_separation(stores[0], stores[1])
        return stores[0], stores[1]
    except Exception:
        raise ValueError(_ERROR) from None
