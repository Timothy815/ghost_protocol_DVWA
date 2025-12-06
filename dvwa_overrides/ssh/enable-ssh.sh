#!/bin/bash
# Enable SSH on DVWA container for training (intentionally weak)
set -e

if ! command -v sshd >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server
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
