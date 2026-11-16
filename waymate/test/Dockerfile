# A stand-in for a freshly rented Ubuntu 26.04 VM: systemd, SSH and Python,
# nothing else. The playbook installs the rest, as on the real VM.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server python3 sudo ca-certificates curl iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl enable ssh.service \
 # A privileged container shares the host's binfmt_misc. Left alone, this
 # systemd would reset it on boot, and on an arm64 laptop that removes the
 # emulation the amd64 container itself runs under.
 && systemctl mask systemd-binfmt.service proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
