# Session Summary - Ghost Protocol DVWA (Dec 6, 2025)

## Key Changes
- Dynamic flags: OP-002 (cmd output/payload), OP-003 (CSRF token in response), OP-005 (live admin hash), OP-006 (stored payload marker), OP-007 (uploaded shell URL/output).
- Priv-esc path: Added writable cron hook (`/etc/cron.d/ghost-cron` -> `/usr/local/bin/ghost-cleanup.sh`) running as root every minute; OP-008 hints updated.
- Remote services exposed: MySQL on 3306 (root/no password); SSH on 2223 with root/ghostuser (passwords set via script).
- Removed universal flag backdoor; documented re-enable in `TEST_BACKDOOR.md`.
- Added sample upload shell: `OP-007_shell_upload/shell.php`.
- DVWA tab now shows URL and “Open in new tab”.
- Prevent XP farming: re-submitting a completed flag no longer adds XP.

## SSH Hardening (for training)
- SSH host keys are no longer tracked in git; `/etc/ssh` is backed by a Docker volume (`ssh_keys`).
- `enable-ssh.sh` installs/starts sshd best-effort from archive.debian.org. If sshd isn’t running, run inside container:
  - `docker exec ghost_target /usr/local/bin/enable-ssh.sh`
  - `docker exec ghost_target /usr/sbin/sshd`
- Credentials: `root:root`, `ghostuser:ghostuser`. Port: `2223`.

## MySQL Exposure (training)
- Port 3306 exposed. `root` with no password. Initialized via `dvwa_overrides/mysql/allow-remote.sql`.

## Priv-Esc (OP-008)
- Writable cron: `/etc/cron.d/ghost-cron` runs `/usr/local/bin/ghost-cleanup.sh` as root every minute. Edit the script to gain root (e.g., `chmod u+s /bin/bash` then `/bin/bash -p`).
- Flags accept root proof (`flag{uid=0(...)}`) and legacy `flag{root_access_granted}`.

## Misc
- Backdoor removed; instructions to re-enable in `TEST_BACKDOOR.md`.
- SSH port changed to 2223 to avoid conflicts.
- Wetty removed; recommend SSH instead.
- Secrets cleanup: committed SSH host keys removed; `.gitignore` excludes `dvwa_overrides/ssh/host_keys/`.

## Usage Notes
- Start stack: `docker-compose up -d --force-recreate`
- If SSH fails, run the two commands above to start sshd, then `ssh -4 -p 2223 root@127.0.0.1`.
- If host key warnings appear once, clear: `ssh-keygen -R "[127.0.0.1]:2223"`.
