# AuditFlow — Automated Security Configuration and Audit Engine

**Authors:** Philip Paul James & Abraham A Wallace  
**Version:** 1.0.0

## File Structure

```
auditflow/
├── app.py                     # Flask web application
├── requirements.txt
├── Dockerfile                 # Vulnerable test target
├── Dockerfile.app             # AuditFlow web app
├── docker-compose.yml
├── sshd_config                # Intentionally vulnerable SSH config
├── vsftpd.conf                # Intentionally insecure FTP
├── smb.conf                   # Samba config
├── entrypoint.sh              # Test target startup
├── auditflow/
│   ├── __init__.py
│   ├── config.py              # App configuration
│   ├── scanner.py             # SSH + port scanner
│   ├── ssh_client.py          # Paramiko SSH wrapper
│   ├── rule_engine.py         # YAML rule evaluator
│   └── reporter.py            # HTML report generator
├── rules/
│   └── ssh_rules.yaml         # CIS-aligned security rules
├── templates/
│   ├── base.html              # Sidebar layout base
│   ├── index.html             # Dashboard
│   ├── new_scan.html          # Scan form
│   ├── scan_status.html       # Live status polling
│   ├── reports.html           # Reports list
│   └── report_view.html       # Full HTML audit report
└── reports/                   # Generated reports (auto-created)
```

---

## Quick Start

### Option A: Run Locally (Python)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start web app
python app.py
# → http://localhost:5000

# 3. (Optional) Spin up vulnerable Docker target
docker build -f Dockerfile -t auditflow-target .
docker run -d \
  --name vuln-target \
  -p 2222:22 -p 2121:21 -p 4445:445 \
  --privileged \
  auditflow-target
```

### Option B: Docker Compose (Full Stack)

```bash
# Build and start everything
docker-compose up -d

# AuditFlow UI → http://localhost:5000
# Vulnerable target SSH → localhost:2222
```

---

## Running a Scan

### Via Web UI
1. Open http://localhost:5000
2. Click **New Scan**
3. Fill in:
   - **Host:** `localhost` (or target IP)
   - **Username:** `root`
   - **Password:** `toor123`
   - **Port Range:** `1-1024`
4. Click **Launch Scan**
5. Wait for completion → auto-redirect to report

### Via CLI (Quick Test — local scan)
```bash
python - <<'EOF'
from auditflow.scanner import Scanner
from auditflow.rule_engine import RuleEngine
from auditflow.reporter import Reporter

scan = Scanner("localhost").run()
results = RuleEngine("rules").evaluate(scan.data)
rid = Reporter("templates", "reports").generate(scan, results)
print(f"Report: reports/report_{rid}.html")
EOF
```

---

## Test Target Credentials

| Service | Host       | Port | Credentials       |
|---------|------------|------|-------------------|
| SSH     | localhost  | 2222 | root / toor123    |
| FTP     | localhost  | 2121 | anonymous         |
| SMB     | localhost  | 4445 | guest             |

**Scan target:**
```
Host: localhost
Port: 2222 (map SSH port in scanner manually, or use the container IP)
User: root
Pass: toor123
```

To scan docker container directly by IP:
```bash
# Get container IP
docker inspect vuln-target | grep IPAddress

# Use that IP in AuditFlow scan form (port 22, not 2222)
```

---

## Expected Test Results (~70% pass / 30% fail)

| Category        | Pass | Fail | Notes                           |
|-----------------|------|------|---------------------------------|
| SSH             | 2/9  | 7/9  | Root login, password auth, etc. |
| Firewall        | 0/2  | 2/2  | UFW disabled                    |
| Ports           | 3/6  | 3/6  | FTP, Telnet-ish, SMB open       |
| Password Policy | 1/4  | 3/4  | Weak rotation policy            |
| Services        | 2/3  | 1/3  | vsftpd running                  |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `paramiko not installed` | `pip install paramiko` |
| SSH connection refused | Check container running: `docker ps` |
| Report not generated | Check `reports/` dir exists, check Flask logs |
| Port 5000 in use | `export FLASK_RUN_PORT=5001; python app.py` |
| Template not found | Run `app.py` from project root directory |
| Docker build fails | Ensure Docker daemon is running |
| Scan shows all INFO | SSH connected but commands returned nothing (check user perms) |

---

## Adding Custom Rules

Edit `rules/ssh_rules.yaml` or add a new `.yaml` file to `rules/`. Rule format:

```yaml
rules:
  - id: my_check
    name: "My Custom Check"
    category: SSH
    severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW
    type: regex_match       # regex_match | exact_match | numeric_lte | numeric_gte | port_open | service_running | boolean
    data_key: ssh_config.parsed.SomeOption
    expected: "^yes$"
    negate: false           # true = FAIL if matched
    expected_display: "yes"
    description: "What this checks and why it matters."
    remediation: |
      Steps to fix the issue.
```

**Available data keys:**
- `ssh_config.parsed.<Option>` — parsed sshd_config values
- `ssh_config.raw` — full sshd_config text
- `firewall.ufw_active` — boolean
- `firewall.any_firewall_active` — boolean
- `password_policy.PASS_MAX_DAYS` etc.
- `services.<service_name>` — boolean (running or not)

---

## Architecture

```
User Browser
    │
    ▼
Flask (app.py)
    │
    ├── Scanner ──── SSHClient (paramiko) ──── Target Host
    │       └────── PortChecker (socket)
    │
    ├── RuleEngine ── rules/*.yaml
    │
    └── Reporter ──── Jinja2 ──── reports/report_*.html
```
