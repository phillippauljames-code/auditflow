"""Scanner - collects security-relevant system data via SSH."""
import re
import logging
import platform
from datetime import datetime
from typing import Optional
from auditflow.ssh_client import SSHClient, check_port_open
from auditflow.config import Config

logger = logging.getLogger(__name__)

# Dangerous ports: (port, service_name)
DANGEROUS_PORTS = [
    (21, "FTP"),
    (23, "Telnet"),
    (445, "SMB"),
    (135, "MS-RPC"),
    (139, "NetBIOS"),
    (3389, "RDP"),
    (5900, "VNC"),
    (6379, "Redis"),
    (27017, "MongoDB"),
]

COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443]


class ScanResult:
    def __init__(self, host: str):
        self.host = host
        self.scan_time = datetime.now().isoformat()
        self.data: dict = {"_host": host}
        self.error: Optional[str] = None
        self.os_info: str = "Unknown"
        self.connection_type: str = "local"


class Scanner:
    def __init__(self, host: str, username: str = "root",
                 password: Optional[str] = None, key_path: Optional[str] = None,
                 port_range: str = "1-1024", timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port_range = port_range
        self.timeout = timeout
        self.ssh: Optional[SSHClient] = None
        self.is_local = host in ("localhost", "127.0.0.1", "::1")

    def run(self) -> ScanResult:
        result = ScanResult(self.host)

        if not self.is_local:
            self.ssh = SSHClient(
                host=self.host,
                username=self.username,
                password=self.password,
                key_path=self.key_path,
                timeout=self.timeout,
            )
            if not self.ssh.connect():
                result.error = f"Could not connect to {self.host} via SSH"
                result.data.update(self._collect_port_data())
                return result
            result.connection_type = "ssh"
        else:
            result.connection_type = "local"

        try:
            result.os_info = self._get_os_info()
            result.data.update({
                "os_info": result.os_info,
                "ssh_config": self._collect_ssh_config(),
                "firewall": self._collect_firewall_data(),
                "password_policy": self._collect_password_policy(),
                "services": self._collect_services(),
                "open_ports": self._collect_port_data(),
                **self._collect_port_data(),
            })
        except Exception as e:
            logger.error(f"Scan error: {e}")
            result.error = str(e)
        finally:
            if self.ssh:
                self.ssh.disconnect()

        return result

    def _run(self, cmd: str) -> str:
        """Run command locally or via SSH."""
        if self.ssh and self.ssh.connected:
            stdout, _, _ = self.ssh.run(cmd)
            return stdout
        else:
            import subprocess
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=self.timeout)
                return out.stdout
            except Exception:
                return ""

    def _get_os_info(self) -> str:
        out = self._run("uname -a 2>/dev/null || ver 2>/dev/null")
        if out.strip():
            return out.strip()[:200]
        return platform.platform()

    def _collect_ssh_config(self) -> dict:
        raw = self._run("cat /etc/ssh/sshd_config 2>/dev/null")
        config = {"raw": raw, "parsed": {}}

        patterns = {
            "PermitRootLogin": r"^\s*PermitRootLogin\s+(\S+)",
            "PasswordAuthentication": r"^\s*PasswordAuthentication\s+(\S+)",
            "PermitEmptyPasswords": r"^\s*PermitEmptyPasswords\s+(\S+)",
            "Protocol": r"^\s*Protocol\s+(\S+)",
            "MaxAuthTries": r"^\s*MaxAuthTries\s+(\d+)",
            "ClientAliveInterval": r"^\s*ClientAliveInterval\s+(\d+)",
            "ClientAliveCountMax": r"^\s*ClientAliveCountMax\s+(\d+)",
            "X11Forwarding": r"^\s*X11Forwarding\s+(\S+)",
            "AllowTcpForwarding": r"^\s*AllowTcpForwarding\s+(\S+)",
            "LoginGraceTime": r"^\s*LoginGraceTime\s+(\S+)",
            "UsePAM": r"^\s*UsePAM\s+(\S+)",
            "Banner": r"^\s*Banner\s+(\S+)",
            "LogLevel": r"^\s*LogLevel\s+(\S+)",
        }

        for key, pattern in patterns.items():
            m = re.search(pattern, raw, re.MULTILINE | re.IGNORECASE)
            config["parsed"][key] = m.group(1) if m else None

        return config

    def _collect_firewall_data(self) -> dict:
        data = {}

        # UFW
        ufw_out = self._run("ufw status 2>/dev/null")
        data["ufw_status"] = ufw_out.strip()
        data["ufw_active"] = "active" in ufw_out.lower() and "inactive" not in ufw_out.lower()

        # iptables
        ipt_out = self._run("iptables -L -n 2>/dev/null | head -30")
        data["iptables_raw"] = ipt_out.strip()
        data["iptables_has_rules"] = bool(ipt_out.strip()) and "Chain" in ipt_out

        # firewalld
        fwd_out = self._run("systemctl is-active firewalld 2>/dev/null")
        data["firewalld_active"] = fwd_out.strip() == "active"

        data["any_firewall_active"] = (
            data["ufw_active"] or data["firewalld_active"]
        )
        return data

    def _collect_password_policy(self) -> dict:
        login_defs = self._run("cat /etc/login.defs 2>/dev/null")
        pam_common = self._run("cat /etc/pam.d/common-password 2>/dev/null")
        pwquality = self._run("cat /etc/security/pwquality.conf 2>/dev/null")

        def extract(text: str, key: str) -> Optional[str]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            return m.group(1) if m else None

        return {
            "PASS_MAX_DAYS": extract(login_defs, "PASS_MAX_DAYS"),
            "PASS_MIN_DAYS": extract(login_defs, "PASS_MIN_DAYS"),
            "PASS_MIN_LEN": extract(login_defs, "PASS_MIN_LEN"),
            "PASS_WARN_AGE": extract(login_defs, "PASS_WARN_AGE"),
            "pam_minlen": self._extract_pam_value(pam_common + pwquality, "minlen"),
            "pam_minclass": self._extract_pam_value(pam_common + pwquality, "minclass"),
            "pam_retry": self._extract_pam_value(pam_common, "retry"),
            "raw_login_defs": login_defs[:500],
        }

    def _extract_pam_value(self, text: str, key: str) -> Optional[str]:
        m = re.search(rf"{re.escape(key)}=(\d+)", text)
        return m.group(1) if m else None

    def _collect_services(self) -> dict:
        services_to_check = [
            "telnet", "ftp", "vsftpd", "proftpd", "rsh", "rlogin",
            "rexec", "nfs", "snmp", "samba", "smbd", "nmbd",
        ]
        result = {}
        for svc in services_to_check:
            out = self._run(f"systemctl is-active {svc} 2>/dev/null || service {svc} status 2>/dev/null | grep -i running")
            result[svc] = "active" in out.lower() or "running" in out.lower()
        return result

    def _collect_port_data(self) -> dict:
        """Check dangerous and common ports."""
        port_results = {"dangerous_ports": {}, "common_ports": {}}

        for port, name in DANGEROUS_PORTS:
            is_open = check_port_open(self.host, port, timeout=2.0)
            port_results["dangerous_ports"][f"{port}_{name}"] = is_open

        for port in COMMON_PORTS:
            is_open = check_port_open(self.host, port, timeout=2.0)
            port_results["common_ports"][str(port)] = is_open

        return port_results
