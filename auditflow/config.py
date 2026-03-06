"""AuditFlow Configuration"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "auditflow-dev-secret-2024")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    RULES_DIR = os.path.join(BASE_DIR, "rules")
    DEFAULT_PORT_RANGE = "1-1024"
    DEFAULT_TIMEOUT = 10
    SSH_PORT = 22

    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }

    # Risk thresholds
    RISK_LEVELS = [
        (80, "LOW", "success"),
        (60, "MEDIUM", "warning"),
        (40, "HIGH", "orange"),
        (0,  "CRITICAL", "danger"),
    ]

    DEVELOPERS = "Philip Paul James & Abraham A Wallace"

os.makedirs(Config.REPORTS_DIR, exist_ok=True)
