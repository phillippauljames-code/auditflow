# AuditFlow - Vulnerable Test Target (Docker)
# Intentional security issues for testing: ~30% FAIL rate
# DO NOT use in production!

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install services
RUN apt-get update && apt-get install -y \
    openssh-server \
    ufw \
    vsftpd \
    telnetd \
    samba \
    xinetd \
    sudo \
    curl \
    net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Create test user and set root password ──────────────────────────────────
RUN echo 'root:toor123' | chpasswd
RUN useradd -m -s /bin/bash testuser && echo 'testuser:testpass' | chpasswd

# ── SSH Config (INTENTIONALLY VULNERABLE) ───────────────────────────────────
RUN mkdir -p /run/sshd /var/run/sshd
COPY sshd_config /etc/ssh/sshd_config

# ── Firewall: DISABLED (intentional) ────────────────────────────────────────
# ufw is installed but NOT enabled → firewall check FAILS

# ── Password Policy: WEAK (intentional) ─────────────────────────────────────
RUN sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t180/' /etc/login.defs && \
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t0/'   /etc/login.defs && \
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t6/'     /etc/login.defs && \
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t3/'   /etc/login.defs

# ── FTP (vsftpd) - enabled but no SSL = FAIL ────────────────────────────────
COPY vsftpd.conf /etc/vsftpd.conf

# ── Samba - running on 445 = FAIL ───────────────────────────────────────────
COPY smb.conf /etc/samba/smb.conf

# ── Startup script ──────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# SSH: port 22 (mapped to 2222 externally)
# FTP: 21
# Samba: 445
EXPOSE 22 21 445

CMD ["/entrypoint.sh"]
