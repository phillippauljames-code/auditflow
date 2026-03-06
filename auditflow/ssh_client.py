"""SSH Client - connects to target and runs remote commands."""
import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SSHClient:
    def __init__(self, host: str, port: int = 22, username: str = "root",
                 password: Optional[str] = None, key_path: Optional[str] = None,
                 timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.timeout = timeout
        self._client = None
        self.connected = False

    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            import paramiko
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = dict(
                hostname=self.host,
                port=self.port,
                username=self.username,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )

            if self.key_path:
                connect_kwargs["key_filename"] = self.key_path
            elif self.password:
                connect_kwargs["password"] = self.password

            self._client.connect(**connect_kwargs)
            self.connected = True
            logger.info(f"Connected to {self.host}:{self.port}")
            return True

        except ImportError:
            logger.error("paramiko not installed - SSH functionality disabled")
            return False
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            return False

    def run(self, command: str) -> tuple[str, str, int]:
        """Execute command, return (stdout, stderr, exit_code)."""
        if not self.connected or not self._client:
            return "", "Not connected", -1
        try:
            _, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
            exit_code = stdout.channel.recv_exit_status()
            return stdout.read().decode("utf-8", errors="replace"), \
                   stderr.read().decode("utf-8", errors="replace"), exit_code
        except Exception as e:
            logger.error(f"Command failed '{command}': {e}")
            return "", str(e), -1

    def get_file(self, remote_path: str) -> Optional[str]:
        """Read remote file contents."""
        stdout, stderr, code = self.run(f"cat {remote_path} 2>/dev/null")
        return stdout if code == 0 else None

    def disconnect(self):
        if self._client:
            self._client.close()
            self.connected = False


def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Quick TCP port check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
