# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.storage.dynamodb_provider — AWS DynamoDB audit node persistence.

Uses ``aioboto3`` (async wrapper around boto3) with a dedicated async session
for non-blocking DynamoDB operations.

Table design
------------
Primary key (simple):
    ``node_id`` (String) — the SHA-256 hex chain link; used for direct lookups.

Global Secondary Index ``aegis_ts_idx`` (required, must be pre-created or
created by ``initialize()``):
    Hash key  : ``partition_key`` (String) — static sentinel ``"ALL"`` written
                to every item.  This collapses all records into a single GSI
                partition, making the index a total-order range scan.
    Range key : ``timestamp`` (String) — ISO 8601 UTC, lexicographic sort.

Caveats
-------
* A single GSI partition ``"ALL"`` works well up to ~10 GB of data (~10 million
  audit nodes).  Beyond that, distribute items across daily shards and update
  ``list_nodes`` to fan-out across shard keys.
* DynamoDB does not support native OFFSET pagination.  ``list_nodes`` implements
  offset as an in-memory skip after a bounded Scan / Query.  For high-volume
  audits, switch to exclusive-start-key cursor pagination.
* ``check_integrity`` performs a full GSI scan and is O(N) in DynamoDB read
  capacity units.  Run it during off-peak hours for large tables.

IAM permissions required::

    dynamodb:PutItem, dynamodb:GetItem, dynamodb:Query,
    dynamodb:Scan, dynamodb:CreateTable, dynamodb:DescribeTable

Dependencies:
    aioboto3>=13.0.0
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aioboto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from aegis_server.storage.base import IntegrityReport, StorageProvider

logger = logging.getLogger(__name__)

_PARTITION_SENTINEL = "ALL"
_GSI_NAME = "aegis_ts_idx"

# DynamoDB attribute type codes
_S = "S"  # String
_N = "N"  # Number (not used here; kept for reference)


class DynamoDBStorageProvider(StorageProvider):
    """
    Async DynamoDB audit node storage using ``aioboto3``.

    Writes are eventually consistent by default.  ``check_integrity`` uses
    ConsistentRead=False on the GSI (GSIs do not support ConsistentRead=True);
    this means very recent nodes (< 1 s) may not yet be visible during the
    integrity sweep.  This is acceptable for forensic audit purposes.

    Args:
        table_name:   DynamoDB table name.
        region:       AWS region, e.g. ``"us-east-1"``.
        endpoint_url: Override endpoint for DynamoDB Local or VPC endpoints.
                      Empty string → use the default AWS endpoint.
    """

    def __init__(
        self,
        table_name: str,
        region: str = "us-east-1",
        endpoint_url: str = "",
    ) -> None:
        if not table_name:
            raise ValueError("DynamoDBStorageProvider requires a non-empty table_name")
        self._table_name = table_name
        self._region = region
        self._endpoint_url: str | None = endpoint_url or None
        self._session: aioboto3.Session | None = None
        self._initialized: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Create an aioboto3 session and ensure the table + GSI exist.

        If the table does not exist it is created with on-demand (PAY_PER_REQUEST)
        billing.  If the table exists the call is a no-op.

        Raises:
            RuntimeError: On AWS API errors that are not ``ResourceInUseException``.
        """
        self._session = aioboto3.Session()

        async with self._get_client() as client:
            try:
                await client.create_table(
                    TableName=self._table_name,
                    AttributeDefinitions=[
                        {"AttributeName": "node_id", "AttributeType": _S},
                        {"AttributeName": "partition_key", "AttributeType": _S},
                        {"AttributeName": "timestamp", "AttributeType": _S},
                    ],
                    KeySchema=[
                        {"AttributeName": "node_id", "KeyType": "HASH"},
                    ],
                    GlobalSecondaryIndexes=[
                        {
                            "IndexName": _GSI_NAME,
                            "KeySchema": [
                                {"AttributeName": "partition_key", "KeyType": "HASH"},
                                {"AttributeName": "timestamp", "KeyType": "RANGE"},
                            ],
                            "Projection": {"ProjectionType": "ALL"},
                        }
                    ],
                    BillingMode="PAY_PER_REQUEST",
                )
                logger.info(
                    "DynamoDB table %r created; waiting for ACTIVE state …",
                    self._table_name,
                )
                # Wait for table to become active (up to 60 s)
                waiter = client.get_waiter("table_exists")
                await waiter.wait(
                    TableName=self._table_name,
                    WaiterConfig={"Delay": 3, "MaxAttempts": 20},
                )
                logger.info("DynamoDB table %r is ACTIVE", self._table_name)

            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceInUseException":
                    logger.debug(
                        "DynamoDB table %r already exists — skipping creation",
                        self._table_name,
                    )
                else:
                    raise RuntimeError(f"DynamoDBStorageProvider.initialize failed: {exc}") from exc

        self._initialized = True
        logger.info(
            "DynamoDBStorageProvider initialised: table=%r region=%r",
            self._table_name,
            self._region,
        )

    async def close(self) -> None:
        """Release the aioboto3 session (connections are per-context-manager)."""
        self._session = None
        self._initialized = False
        logger.debug("DynamoDBStorageProvider session released")

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def write_node(
        self,
        node_id: str,
        timestamp: str,
        node_data: dict[str, Any],
        request_hash: str,
        response_hash: str,
        merkle_root: str,
        signature: str,
        client_id: str,
    ) -> None:
        """
        Write an audit node via ``PutItem`` with a condition that prevents
        overwriting an existing record (idempotent on duplicate ``node_id``).

        Raises:
            RuntimeError: On unrecoverable AWS API errors.
        """
        self._require_initialized()

        item: dict[str, Any] = {
            "node_id": node_id,
            "partition_key": _PARTITION_SENTINEL,
            "timestamp": timestamp,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "merkle_root": merkle_root,
            "signature": signature,
            "client_id": client_id,
            # DynamoDB does not have a native JSON column type — store as string.
            "node_data": json.dumps(node_data, separators=(",", ":"), default=str),
        }

        try:
            async with self._get_resource() as dynamodb:
                table = await dynamodb.Table(self._table_name)
                await table.put_item(
                    Item=item,
                    ConditionExpression="attribute_not_exists(node_id)",
                )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ConditionalCheckFailedException":
                # node_id already exists — idempotent, not an error
                logger.debug("DynamoDB PutItem skipped: node_id=%r already exists", node_id)
                return
            raise RuntimeError(
                f"DynamoDBStorageProvider.write_node failed for node_id={node_id!r}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_latest_node(self) -> dict[str, Any] | None:
        """
        Return the most recently inserted audit node, or None.

        BLOCKER-NEW fix: implements the abstract method added to StorageProvider
        in v2.2.0.

        Uses the ``aegis_ts_idx`` GSI with ``ScanIndexForward=False`` and
        ``Limit=1`` to retrieve the item with the highest (most recent)
        ISO-8601 UTC timestamp.  ISO-8601 strings are lexicographically
        monotonic so this ordering is correct.

        Note: DynamoDB does not support process-local or distributed row locks.
        For multi-worker chain-fork prevention, implement an external Redlock
        on the "chain write" critical section.
        """
        self._require_initialized()
        try:
            async with self._get_resource() as dynamodb:
                table = await dynamodb.Table(self._table_name)
                response = await table.query(
                    IndexName=_GSI_NAME,
                    KeyConditionExpression=Key("partition_key").eq(_PARTITION_SENTINEL),
                    ScanIndexForward=False,  # descending → most recent first
                    Limit=1,
                )
            items = response.get("Items", [])
            if not items:
                return None
            return self._item_to_dict(items[0])
        except Exception as exc:
            raise RuntimeError(f"DynamoDBStorageProvider.get_latest_node failed: {exc}") from exc

    async def get_node(self, node_hash: str) -> dict[str, Any] | None:
        """
        Retrieve a node by SHA-256 hash via ``GetItem`` (strongly consistent).

        Returns:
            Dict compatible with ``StorageNode.from_dict``, or ``None``.
        """
        self._require_initialized()

        try:
            async with self._get_resource() as dynamodb:
                table = await dynamodb.Table(self._table_name)
                response = await table.get_item(
                    Key={"node_id": node_hash},
                    ConsistentRead=True,
                )
        except ClientError as exc:
            raise RuntimeError(
                f"DynamoDBStorageProvider.get_node failed for hash={node_hash!r}: {exc}"
            ) from exc

        item = response.get("Item")
        if item is None:
            return None
        return self._item_to_dict(item)

    async def list_nodes(
        self,
        limit: int,
        offset: int,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return paginated nodes ordered by timestamp via the ``aegis_ts_idx`` GSI.

        Because DynamoDB does not support server-side OFFSET, the implementation
        fetches ``offset + limit`` items and skips the first ``offset`` entries
        in memory.  For very large offsets, use exclusive-start-key pagination.

        Raises:
            ValueError:   If ``offset < 0``.
            RuntimeError: On AWS API errors.
        """
        self._require_initialized()
        clamped = self._clamp_limit(limit)
        offset = self._validate_offset(offset)
        fetch_limit = offset + clamped

        filter_expr = Attr("client_id").eq(tenant_id) if tenant_id else None

        collected: list[dict[str, Any]] = []
        last_key: dict[str, Any] | None = None

        try:
            async with self._get_resource() as dynamodb:
                table = await dynamodb.Table(self._table_name)

                while len(collected) < fetch_limit:
                    query_kwargs: dict[str, Any] = {
                        "IndexName": _GSI_NAME,
                        "KeyConditionExpression": Key("partition_key").eq(_PARTITION_SENTINEL),
                        "ScanIndexForward": True,
                        "Limit": min(1000, fetch_limit - len(collected) + 50),
                    }
                    if filter_expr is not None:
                        query_kwargs["FilterExpression"] = filter_expr
                    if last_key is not None:
                        query_kwargs["ExclusiveStartKey"] = last_key

                    response = await table.query(**query_kwargs)
                    items = response.get("Items", [])
                    collected.extend(items)
                    last_key = response.get("LastEvaluatedKey")

                    if last_key is None:
                        break  # exhausted the table / filtered result set

        except ClientError as exc:
            raise RuntimeError(f"DynamoDBStorageProvider.list_nodes failed: {exc}") from exc

        # Apply in-memory offset and limit
        page = collected[offset : offset + clamped]
        return [self._item_to_dict(i) for i in page]

    async def check_integrity(self) -> dict[str, Any]:
        """
        Full GSI scan + chain linkage verification.

        Uses ``ScanIndexForward=True`` on the timestamp GSI to get ascending
        order.  ConsistentRead is not supported on GSIs.

        Returns:
            ``IntegrityReport.to_dict()``-compatible dict.
        """
        self._require_initialized()
        checked_at = self._utcnow_iso()

        all_nodes: list[dict[str, Any]] = []
        last_key: dict[str, Any] | None = None

        try:
            async with self._get_resource() as dynamodb:
                table = await dynamodb.Table(self._table_name)
                while True:
                    query_kwargs: dict[str, Any] = {
                        "IndexName": _GSI_NAME,
                        "KeyConditionExpression": Key("partition_key").eq(_PARTITION_SENTINEL),
                        "ScanIndexForward": True,
                        "Limit": 1000,
                    }
                    if last_key is not None:
                        query_kwargs["ExclusiveStartKey"] = last_key

                    response = await table.query(**query_kwargs)
                    all_nodes.extend(response.get("Items", []))
                    last_key = response.get("LastEvaluatedKey")
                    if last_key is None:
                        break
        except ClientError as exc:
            raise RuntimeError(f"DynamoDBStorageProvider.check_integrity failed: {exc}") from exc

        if not all_nodes:
            return IntegrityReport(
                is_valid=True,
                node_count=0,
                first_node_id=None,
                last_node_id=None,
                broken_link_index=None,
                error_message=None,
                checked_at=checked_at,
            ).to_dict()

        first_id: str = all_nodes[0]["node_id"]
        last_id: str = all_nodes[-1]["node_id"]
        prev_node_id: str = "0" * 64

        for i, item in enumerate(all_nodes):
            current_id: str = item["node_id"]
            raw_nd = item.get("node_data", "{}")
            try:
                node_data: dict[str, Any] = (
                    json.loads(raw_nd) if isinstance(raw_nd, str) else raw_nd
                )
            except (json.JSONDecodeError, ValueError):
                node_data = {}

            stored_prev: str = node_data.get("prev_hash", "")
            if stored_prev != prev_node_id:
                return IntegrityReport(
                    is_valid=False,
                    node_count=len(all_nodes),
                    first_node_id=first_id,
                    last_node_id=last_id,
                    broken_link_index=i,
                    error_message=(
                        f"Node {i} (id={current_id[:16]}…): "
                        f"prev_hash mismatch — "
                        f"expected={prev_node_id[:16]}…, "
                        f"stored={stored_prev[:16] if stored_prev else '(empty)'}…"
                    ),
                    checked_at=checked_at,
                ).to_dict()

            prev_node_id = current_id

        return IntegrityReport(
            is_valid=True,
            node_count=len(all_nodes),
            first_node_id=first_id,
            last_node_id=last_id,
            broken_link_index=None,
            error_message=None,
            checked_at=checked_at,
        ).to_dict()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_initialized(self) -> None:
        if not self._initialized or self._session is None:
            raise RuntimeError("DynamoDBStorageProvider.initialize() was not called")

    def _get_client(self):
        """Async context manager for a low-level DynamoDB client."""
        kwargs: dict[str, Any] = {"region_name": self._region}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        return self._session.client("dynamodb", **kwargs)  # type: ignore[union-attr]

    def _get_resource(self):
        """Async context manager for the DynamoDB resource (Table API)."""
        kwargs: dict[str, Any] = {"region_name": self._region}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        return self._session.resource("dynamodb", **kwargs)  # type: ignore[union-attr]

    @staticmethod
    def _item_to_dict(item: dict[str, Any]) -> dict[str, Any]:
        """Normalize a DynamoDB item to the standard StorageNode dict shape."""
        d = {k: v for k, v in item.items() if k != "partition_key"}
        raw_nd = d.get("node_data", "{}")
        if isinstance(raw_nd, str):
            try:
                d["node_data"] = json.loads(raw_nd)
            except (json.JSONDecodeError, ValueError):
                d["node_data"] = {}
        elif not isinstance(raw_nd, dict):
            d["node_data"] = {}
        return d
