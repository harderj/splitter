#!/usr/bin/env bash
# One-time (and safe to re-run) hardening and setup of a fresh Ubuntu VPS for Splitter.
#
#   sudo deploy/setup-server.sh splitter.info
#
# Before running: make sure you can log in with an SSH key, because password
# login is disabled by this script.
set -euo pipefail

DOMAIN="${1:?usage: sudo $0 <domain>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ADMIN_USER="${SUDO_USER:-ubuntu}"

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
if [[ ! -s "/home/$ADMIN_USER/.ssh/authorized_keys" ]]; then
	echo "No SSH key in /home/$ADMIN_USER/.ssh/authorized_keys -- refusing to disable password login." >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
echo "==> Packages"
apt-get update -qq
apt-get install -y -qq ufw fail2ban caddy sqlite3 unattended-upgrades build-essential pkg-config >/dev/null

echo "==> SSH: keys only, no root login"
# cloud-init drops a 50-cloud-init.conf that may enable passwords; the first
# value sshd sees wins, so our 10- file takes precedence.
cat >/etc/ssh/sshd_config.d/10-hardening.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
CONF
[[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]] &&
	sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
sshd -t
systemctl reload ssh
passwd -l "$ADMIN_USER" >/dev/null
passwd -l root >/dev/null

echo "==> Firewall"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw limit 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

echo "==> fail2ban"
cat >/etc/fail2ban/jail.local <<'CONF'
[DEFAULT]
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
mode = aggressive
CONF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

echo "==> Automatic security updates"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
systemctl enable --now unattended-upgrades >/dev/null 2>&1

echo "==> App user and services"
id splitter >/dev/null 2>&1 ||
	useradd --system --home-dir /var/lib/splitter --no-create-home --shell /usr/sbin/nologin splitter
install -d -o root -g root -m 755 /opt/splitter
install -m 644 "$HERE/splitter.service" "$HERE/splitter-backup.service" "$HERE/splitter-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable splitter.service splitter-backup.timer >/dev/null 2>&1
systemctl start splitter-backup.timer

echo "==> Caddy (HTTPS reverse proxy for $DOMAIN)"
sed "s/__DOMAIN__/$DOMAIN/g" "$HERE/Caddyfile" >/etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1
systemctl enable caddy >/dev/null 2>&1
systemctl reload-or-restart caddy

echo
echo "Server set up. Next: deploy/deploy.sh to build and start the app."
echo "Make sure the DNS A records for $DOMAIN and www.$DOMAIN point to this server."
