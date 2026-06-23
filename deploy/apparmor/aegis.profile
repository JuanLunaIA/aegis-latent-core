#include <tunables/global>

profile aegis-latent-core flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/python>

  # Allow read of config files
  /etc/aegis/** r,
  /home/** r,

  # WAL and log directories
  /var/lib/aegis/** rw,
  /tmp/aegis/** rw,

  # Network (outbound only to configured upstreams)
  network tcp,

  # Deny dangerous syscalls (complement to seccomp)
  deny /proc/sysrq-trigger w,
  deny /proc/*/mem rw,
  deny /sys/kernel/debug/** rw,
}
