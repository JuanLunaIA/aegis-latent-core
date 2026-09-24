#include <tunables/global>

# AppArmor profile for the Aegis gateway container, as `docker-compose.yml`
# applies it (`security_opt: apparmor=aegis-latent-core`). Load it on the host
# before starting the container:
#
#   sudo apparmor_parser -r -W deploy/apparmor/aegis.profile
#
# The first CI run under this profile also denied an exec of /usr/sbin/ldconfig:
# the gateway ran ldconfig to locate libc (REG-D83). That was fixed in the code,
# not granted here — nothing in the gateway needs to execute a program.
#
# REG-D80: the previous profile granted writes only under /var/lib/aegis and
# /tmp/aegis, while the image and compose keep the WAL at /data, and it granted
# nothing to execute the interpreter or read the installed application — the
# compose deployment it was written for could not start under it. The rules
# below follow what the gateway actually touches, and the CI container smoke
# test (`scripts/container_smoke_test.py --apparmor aegis-latent-core`) starts
# the image under this profile on every change.

profile aegis-latent-core flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  # The interpreter, the console-script entry point and the installed packages
  # (the image installs everything under /usr/local). The seccomp filter the
  # gateway loads at startup forbids execve afterwards; `ix` here covers the
  # container entry point and the image's own HEALTHCHECK.
  /usr/local/bin/ r,
  /usr/local/bin/** rmix,
  /usr/local/lib/** rm,
  /app/ r,
  /app/** r,

  # Configuration and operator-mounted material (TLS CA/cert/key files), and
  # OpenSSL's own configuration, read when the TLS context is built.
  /etc/aegis/ r,
  /etc/aegis/** r,
  /etc/ssl/openssl.cnf r,
  /etc/localtime r,
  /usr/share/zoneinfo/** r,

  # Durable evidence: the image's WAL lives under /data (AEGIS_WAL_PATH); the
  # writer takes an exclusive lock (k) and publishes identity files with an
  # atomic hard link (l). /var/lib/aegis is the non-container default.
  /data/ r,
  /data/** rwkl,
  /var/lib/aegis/ r,
  /var/lib/aegis/** rwkl,
  /tmp/ r,
  /tmp/** rwk,

  # Self-inspection the startup posture checks perform: seccomp and
  # no-new-privs status, LSM confinement, open io_uring descriptors, cgroup
  # quotas and the allocator probe.
  @{PROC}/@{pid}/status r,
  @{PROC}/@{pid}/attr/current r,
  @{PROC}/@{pid}/attr/apparmor/current r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/@{pid}/fd/* r,
  @{PROC}/@{pid}/maps r,
  @{PROC}/@{pid}/mounts r,
  @{PROC}/@{pid}/mountinfo r,
  @{PROC}/@{pid}/cgroup r,
  @{PROC}/@{pid}/stat r,
  # prometheus_client's process collector reads the fd limit (REG-D86).
  @{PROC}/@{pid}/limits r,
  /sys/fs/cgroup/ r,
  /sys/fs/cgroup/** r,
  /sys/module/apparmor/parameters/enabled r,
  /sys/devices/system/cpu/** r,
  @{PROC}/version r,
  @{PROC}/version_signature r,

  # Network: clients inbound, the upstream provider and Redis outbound, DNS,
  # and the netlink route query glibc's getaddrinfo makes for AI_ADDRCONFIG.
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,

  # `docker stop` delivers SIGTERM from the unconfined runtime; the gateway's
  # threads signal each other during shutdown.
  signal (receive) peer=unconfined,
  signal (send, receive) peer=aegis-latent-core,

  # Explicit denials (complement to the seccomp filter).
  deny /proc/sysrq-trigger rw,
  deny /proc/*/mem rw,
  deny /sys/kernel/debug/** rw,
  deny mount,
  deny umount,
  deny ptrace,
}
