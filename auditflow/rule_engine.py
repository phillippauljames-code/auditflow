"""Rule Engine - evaluates YAML rules against collected system data."""
import re
import yaml
import logging
from typing import Any
from pathlib import Path

logger = logging.getLogger(__name__)


class RuleResult:
    def __init__(self, rule_id: str, name: str, status: str, severity: str,
                 category: str, description: str, current_value: str,
                 expected_value: str, remediation: str):
        self.rule_id = rule_id
        self.name = name
        self.status = status       # "PASS" | "FAIL" | "WARN" | "INFO"
        self.severity = severity   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        self.category = category
        self.description = description
        self.current_value = current_value
        self.expected_value = expected_value
        self.remediation = remediation

    def to_dict(self) -> dict:
        return self.__dict__


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_all_rules()

    def _load_all_rules(self) -> list[dict]:
        rules = []
        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "rules" in data:
                        for rule in data["rules"]:
                            rule["_source"] = yaml_file.stem
                        rules.extend(data["rules"])
            except Exception as e:
                logger.error(f"Failed to load {yaml_file}: {e}")
        logger.info(f"Loaded {len(rules)} rules")
        return rules

    def evaluate(self, collected_data: dict) -> list[RuleResult]:
        results = []
        for rule in self.rules:
            try:
                result = self._evaluate_rule(rule, collected_data)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Rule {rule.get('id', '?')} error: {e}")
        return results

    def _evaluate_rule(self, rule: dict, data: dict) -> RuleResult | None:
        rule_id = rule.get("id", "unknown")
        check_type = rule.get("type", "")
        data_key = rule.get("data_key", "")
        category = rule.get("category", rule.get("_source", "General"))

        # Get the data value to check
        value = self._get_nested(data, data_key)

        status, current_display = self._run_check(rule, check_type, value, data)

        return RuleResult(
            rule_id=rule_id,
            name=rule.get("name", rule_id),
            status=status,
            severity=rule.get("severity", "MEDIUM"),
            category=category,
            description=rule.get("description", ""),
            current_value=current_display,
            expected_value=rule.get("expected_display", rule.get("expected", "")),
            remediation=rule.get("remediation", ""),
        )

    def _run_check(self, rule: dict, check_type: str, value: Any, data: dict) -> tuple[str, str]:
        """Returns (status, current_display)."""
        expected = rule.get("expected", "")
        negate = rule.get("negate", False)  # True = fail if match found

        if value is None and check_type not in ("port_open", "port_closed"):
            return "INFO", "Data not available"

        if check_type == "regex_match":
            matched = bool(re.search(str(expected), str(value), re.MULTILINE))
            passed = not matched if negate else matched
            return ("PASS" if passed else "FAIL"), str(value)[:500]

        elif check_type == "exact_match":
            passed = str(value).strip() == str(expected)
            passed = not passed if negate else passed
            return ("PASS" if passed else "FAIL"), str(value)[:200]

        elif check_type == "numeric_lte":
            try:
                passed = int(str(value).strip()) <= int(expected)
                passed = not passed if negate else passed
                return ("PASS" if passed else "FAIL"), str(value)
            except ValueError:
                return "INFO", f"Could not parse: {value}"

        elif check_type == "numeric_gte":
            try:
                passed = int(str(value).strip()) >= int(expected)
                passed = not passed if negate else passed
                return ("PASS" if passed else "FAIL"), str(value)
            except ValueError:
                return "INFO", f"Could not parse: {value}"

        elif check_type == "port_open":
            from auditflow.ssh_client import check_port_open
            host = data.get("_host", "")
            port = rule.get("port", 0)
            is_open = check_port_open(host, port) if host else False
            # negate=True means: FAIL if port IS open (dangerous port)
            passed = not is_open if negate else is_open
            return ("PASS" if passed else "FAIL"), f"Port {port}: {'OPEN' if is_open else 'CLOSED'}"

        elif check_type == "service_running":
            service = rule.get("service", "")
            svc_data = data.get("services", {})
            is_running = svc_data.get(service, False)
            passed = not is_running if negate else is_running
            return ("PASS" if passed else "FAIL"), f"{'Running' if is_running else 'Stopped'}"

        elif check_type == "boolean":
            passed = bool(value) == bool(expected)
            passed = not passed if negate else passed
            return ("PASS" if passed else "FAIL"), str(value)

        return "INFO", str(value)[:200] if value else "N/A"

    @staticmethod
    def _get_nested(data: dict, key_path: str) -> Any:
        """Traverse dot-separated key path."""
        if not key_path:
            return None
        parts = key_path.split(".")
        current = data
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
