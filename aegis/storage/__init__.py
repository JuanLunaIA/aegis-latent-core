"""Production storage integrations."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.

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
