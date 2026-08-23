"""Production storage integrations."""

from aegis.storage.s3_worm import (
    ArchiveRecord,
    ArchiveState,
    Boto3S3WormProvider,
    ChecksumMismatchError,
    HeadObjectResult,
    ObjectLockMode,
    PutObjectResult,
    QueueCapacityError,
    S3WormArchiver,
    S3WormProvider,
    SpoolCapacityError,
)
from aegis.storage.segment_manifest import (
    SegmentManifest,
    archive_finalized_segment,
    build_segment_manifest,
)

__all__ = [
    "ArchiveRecord",
    "ArchiveState",
    "Boto3S3WormProvider",
    "ChecksumMismatchError",
    "HeadObjectResult",
    "ObjectLockMode",
    "PutObjectResult",
    "QueueCapacityError",
    "S3WormArchiver",
    "S3WormProvider",
    "SegmentManifest",
    "SpoolCapacityError",
    "archive_finalized_segment",
    "build_segment_manifest",
]
