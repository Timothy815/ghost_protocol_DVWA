#!/bin/bash
# Enable SSH on DVWA container for training (intentionally weak)
set -e

# Point to archived Debian stretch repositories to avoid 404s
if ! grep -q "archive.debian.org" /etc/apt/sources.list; then
    cat >/etc/apt/sources.list <<'EOF'
deb http://archive.debian.org/debian stretch main contrib non-free
deb http://archive.debian.org/debian-security stretch/updates main contrib non-free
EOF
fi
echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99disable-check-valid-until
cat >/etc/apt/apt.conf.d/99insecure <<'EOF'
Acquire::AllowInsecureRepositories "true";
Acquire::AllowDowngradeToInsecureRepositories "true";
APT::Get::AllowUnauthenticated "true";
EOF

if ! command -v sshd >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated openssh-server
fi

mkdir -p /var/run/sshd

# Ensure password auth and root login are allowed (unsafe on purpose)
if ! grep -q '^PasswordAuthentication' /etc/ssh/sshd_config; then
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
else
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
fi

if ! grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
else
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
fi

# Create a weak user for SSH practice
if ! id ghostuser >/dev/null 2>&1; then
    useradd -m -s /bin/bash ghostuser
fi
echo 'ghostuser:ghostuser' | chpasswd
echo 'root:root' | chpasswd

# Generate host keys if missing
ssh-keygen -A

service ssh restart
