#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# Run ON the Azure VM created by the kit (as root). Records what the repo's own harness and
# the raw data disk measure there, plus the environment they ran in, into one JSON artifact.
# It stops the gateway while measuring so the numbers are not contended, and restarts it after.
#
#   sudo ./run_azure_benchmarks.sh --commit <git-sha> [--out /root/azure-bench.json]
#
# Boundary (docs/benchmarks/AZURE_BENCHMARKS.md): observations on one VM on one date. Not a
# capacity claim, a service level, or a statement about any other size, region or disk.
set -euo pipefail

COMMIT=""; OUT=/root/azure-bench.json
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || { echo "--commit <git sha of the repo state to measure> is required" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
. /etc/aegis/kit.env
WORK=/var/lib/aegis/bench            # on the WAL data disk: fsync numbers describe that disk
SRC=/root/aegis-src

apt-get install -y -qq fio git jq >/dev/null
rm -rf "$SRC" "$WORK"; mkdir -p "$WORK"; chown 10001:10001 "$WORK"
git clone -q https://github.com/JuanLunaIA/aegis-latent-core "$SRC"
git -C "$SRC" checkout -q "$COMMIT"
FULL=$(git -C "$SRC" rev-parse HEAD)

systemctl stop aegis.service
trap 'systemctl start aegis.service' EXIT
docker pull -q "$AEGIS_IMAGE" >/dev/null
DIGEST=$(docker image inspect "$AEGIS_IMAGE" --format '{{index .RepoDigests 0}}')

IMDS=$(curl -fsS -H Metadata:true "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01")
ENVJSON=$(jq -n --argjson i "$IMDS" \
  --arg kernel "$(uname -r)" --arg cpu "$(lscpu | sed -n 's/^Model name: *//p')" \
  --arg vcpus "$(nproc)" --arg mem "$(free -m | awk '/Mem:/{print $2}')" \
  --arg fs "$(findmnt -no FSTYPE,OPTIONS /var/lib/aegis)" --arg docker "$(docker --version)" \
  '{vmSize:$i.vmSize, location:$i.location, zone:$i.zone, imageSku:$i.storageProfile.imageReference.sku,
    dataDisks:[$i.storageProfile.dataDisks[]|{sizeGb:.diskSizeGB, sku:.managedDisk.storageAccountType, caching:.caching}],
    kernel:$kernel, cpu:$cpu, vcpus:($vcpus|tonumber), memMiB:($mem|tonumber), walMount:$fs, docker:$docker}')
# subscriptionId, resourceGroupName, vmId and name are deliberately not copied out of IMDS.

echo "[1/3] raw disk: 4 KiB sequential writes, fsync after every write, 30 s"
FIO=$(fio --name=fsync4k --directory="$WORK" --rw=write --bs=4k --size=128m --fsync=1 \
  --ioengine=sync --runtime=30 --time_based --output-format=json)
FIOJSON=$(jq '.jobs[0] as $j | {writes_with_fsync_per_second:$j.write.iops, fsync_count:$j.sync.total_ios,
  fsync_ms:{p50:($j.sync.lat_ns.percentile["50.000000"]/1e6), p95:($j.sync.lat_ns.percentile["95.000000"]/1e6),
            p99:($j.sync.lat_ns.percentile["99.000000"]/1e6), mean:($j.sync.lat_ns.mean/1e6), max:($j.sync.lat_ns.max/1e6)}}' <<<"$FIO")

echo "[2/3] repo harness inside the release image, WAL temp dir on the data disk"
HARNESS=$(docker run --rm --network none --user 10001:10001 --read-only --cap-drop ALL \
  -e TMPDIR=/wal -e PYTHONPATH=/bench -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$WORK":/wal -v "$SRC/scripts":/bench/scripts:ro -v "$SRC/benchmarks":/bench/benchmarks:ro \
  -w /bench --tmpfs /tmp:size=64m --entrypoint python "$AEGIS_IMAGE" \
  scripts/run_benchmarks_5.0.1.py --json)

echo "[3/3] client-visible GET /health through Caddy TLS from this VM, 300 sequential requests"
systemctl start aegis.service; trap - EXIT
for _ in $(seq 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "https://$AEGIS_FQDN/health" || true)" = 200 ] && break; sleep 5
done
TIMES=$(for _ in $(seq 300); do curl -s -o /dev/null -w '%{time_total}\n' -m 10 "https://$AEGIS_FQDN/health"; done | sort -n)
HEALTH=$(awk '{a[NR]=$1} END{printf "{\"n\":%d,\"p50_ms\":%.2f,\"p95_ms\":%.2f,\"p99_ms\":%.2f,\"max_ms\":%.2f}",
  NR, a[int(NR*0.50)]*1000, a[int(NR*0.95)]*1000, a[int(NR*0.99)]*1000, a[NR]*1000}' <<<"$TIMES")

jq -n --arg date "$(date -u +%FT%TZ)" --arg commit "$FULL" --arg image "$AEGIS_IMAGE" --arg digest "$DIGEST" \
  --argjson env "$ENVJSON" --argjson fio "$FIOJSON" --argjson harness "$HARNESS" --argjson health "$HEALTH" \
  '{schema:"aegis-azure-bench-1", date:$date, repoCommit:$commit, image:$image, imageDigest:$digest,
    environment:$env, rawDiskFsync4k:$fio, repoHarness:$harness, healthEndpoint:$health,
    boundary:"Observations on one Azure VM on one date. Not a capacity claim, service level or production figure."}' > "$OUT"
sha256sum "$OUT"
echo "wrote $OUT"
