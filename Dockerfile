# Use the official rolling Kali image
FROM kalilinux/kali-rolling

# Non-interactive installation to prevent hanging
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Core Tools (Nmap, SQLMap, Hydra, Curl, etc.)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    net-tools \
    iputils-ping \
    nmap \
    hydra \
    sqlmap \
    python3 \
    jq \
    && rm -rf /var/lib/apt/lists/*

# 2. Install shellinabox + openssh-server (SSH gives cleaner terminal)
RUN apt-get update && apt-get install -y shellinabox openssh-server \
    && rm -rf /var/lib/apt/lists/*

# 3. Setup the Shell
WORKDIR /root
SHELL ["/bin/bash", "-c"]

# 4. Enable passwordless root login for shellinabox
RUN passwd -d root

# 5. Configure clean bash environment (no wrapper - let shellinabox manage PTY)
RUN touch ~/.hushlogin && \
    echo > /etc/motd && \
    echo > /etc/issue && \
    echo > /etc/issue.net && \
    truncate -s 0 /etc/motd /etc/issue /etc/issue.net && \
    sed -i '/^PS1=/d' /root/.bashrc && \
    sed -i '/^export PS1=/d' /root/.bashrc && \
    echo 'export PS1="root@\h:\w$ "' >> /root/.bashrc && \
    sed -i '/^PS1=/d' /etc/bash.bashrc 2>/dev/null || true && \
    sed -i '/^export PS1=/d' /etc/bash.bashrc 2>/dev/null || true

# 8. Create startup script with LOGIN service for better terminal compatibility
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'exec /usr/bin/shellinaboxd -t -s /:LOGIN 2>/dev/null' >> /start.sh && \
    chmod +x /start.sh

# 9. Expose the Web Terminal Port
EXPOSE 8080

# 10. Start with wrapper script
CMD ["/start.sh"]