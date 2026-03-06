"""Reporter - generates professional HTML security audit reports."""
import os
import json
import uuid
import logging
from datetime import datetime
from typing import Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from auditflow.config import Config
from auditflow.rule_engine import RuleResult

logger = logging.getLogger(__name__)

# Category display order
CATEGORY_ORDER = ["SSH", "Firewall", "Ports", "Password Policy", "Services"]


def compute_score(results: list[RuleResult]) -> dict:
    """Compute compliance score and risk level."""
    weights = Config.SEVERITY_WEIGHTS
    total_weight = sum(weights.get(r.severity, 1) for r in results
                       if r.status in ("PASS", "FAIL"))
    pass_weight = sum(weights.get(r.severity, 1) for r in results if r.status == "PASS")

    score = round((pass_weight / total_weight * 100) if total_weight else 0)

    risk = "CRITICAL"
    risk_color = "danger"
    for threshold, level, color in Config.RISK_LEVELS:
        if score >= threshold:
            risk = level
            risk_color = color
            break

    # Score color
    if score >= 80:
        score_color = "success"
    elif score >= 60:
        score_color = "warning"
    elif score >= 40:
        score_color = "orange"
    else:
        score_color = "danger"

    # Category breakdown
    categories: dict[str, dict] = {}
    for r in results:
        cat = r.category
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0, "total": 0}
        categories[cat]["total"] += 1
        if r.status == "PASS":
            categories[cat]["pass"] += 1
        elif r.status == "FAIL":
            categories[cat]["fail"] += 1

    for cat, counts in categories.items():
        t = counts["pass"] + counts["fail"]
        counts["score"] = round(counts["pass"] / t * 100) if t else 0

    return {
        "score": score,
        "score_color": score_color,
        "risk": risk,
        "risk_color": risk_color,
        "total": len(results),
        "passed": sum(1 for r in results if r.status == "PASS"),
        "failed": sum(1 for r in results if r.status == "FAIL"),
        "info": sum(1 for r in results if r.status == "INFO"),
        "categories": categories,
    }


class Reporter:
    def __init__(self, templates_dir: str, reports_dir: str):
        self.reports_dir = reports_dir
        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html"]),
        )
        os.makedirs(reports_dir, exist_ok=True)

    def generate(self, scan_result, rule_results: list[RuleResult],
                 report_id: Optional[str] = None) -> str:
        """Generate HTML report, return report_id."""
        report_id = report_id or str(uuid.uuid4())[:8]
        scoring = compute_score(rule_results)

        # Group results by category
        grouped: dict[str, list[RuleResult]] = {}
        for r in rule_results:
            grouped.setdefault(r.category, []).append(r)

        # Sort: FAIL first, then by severity weight
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for cat in grouped:
            grouped[cat].sort(key=lambda r: (
                0 if r.status == "FAIL" else 1,
                sev_order.get(r.severity, 4)
            ))

        context = {
            "report_id": report_id,
            "host": scan_result.host,
            "scan_time": scan_result.scan_time,
            "os_info": getattr(scan_result, "os_info", "Unknown"),
            "connection_type": getattr(scan_result, "connection_type", "local"),
            "scoring": scoring,
            "results": rule_results,
            "grouped": grouped,
            "category_order": CATEGORY_ORDER,
            "developers": Config.DEVELOPERS,
            "scan_error": getattr(scan_result, "error", None),
        }

        template = self.env.get_template("report_view.html")
        html = template.render(**context)

        # Save report
        report_path = os.path.join(self.reports_dir, f"report_{report_id}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        # Save metadata JSON for listing
        meta = {
            "report_id": report_id,
            "host": scan_result.host,
            "scan_time": scan_result.scan_time,
            "score": scoring["score"],
            "risk": scoring["risk"],
            "risk_color": scoring["risk_color"],
            "passed": scoring["passed"],
            "failed": scoring["failed"],
            "total": scoring["total"],
        }
        meta_path = os.path.join(self.reports_dir, f"meta_{report_id}.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f)

        logger.info(f"Report saved: {report_path}")
        return report_id

    @staticmethod
    def list_reports(reports_dir: str) -> list[dict]:
        """Return list of report metadata, newest first."""
        metas = []
        try:
            for fname in os.listdir(reports_dir):
                if fname.startswith("meta_") and fname.endswith(".json"):
                    with open(os.path.join(reports_dir, fname)) as f:
                        metas.append(json.load(f))
        except Exception as e:
            logger.error(f"Error listing reports: {e}")
        return sorted(metas, key=lambda m: m.get("scan_time", ""), reverse=True)

    @staticmethod
    def delete_report(reports_dir: str, report_id: str) -> bool:
        """Delete report HTML and metadata."""
        deleted = False
        for fname in [f"report_{report_id}.html", f"meta_{report_id}.json"]:
            path = os.path.join(reports_dir, fname)
            if os.path.exists(path):
                os.remove(path)
                deleted = True
        return deleted
