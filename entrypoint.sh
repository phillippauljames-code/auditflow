#!/bin/bash
# AuditFlow Test Target - Startup Script

# Generate SSH host keys
ssh-keygen -A 2>/dev/null

# Start SSH
service ssh start

# Start FTP (intentional - for testing)
service vsftpd start 2>/dev/null || true

# Start Samba (intentional - for testing)
mkdir -p /tmp/public
service smbd start 2>/dev/null || true
service nmbd start 2>/dev/null || true

echo "=================================="
echo " AuditFlow Vulnerable Test Target"
echo "=================================="
echo " SSH:    port 22  (root:toor123)"
echo " FTP:    port 21  (anonymous)"
echo " Samba:  port 445"
echo " Firewall: DISABLED"
echo "=================================="

# Keep container running
tail -f /dev/null
