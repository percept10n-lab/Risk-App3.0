import structlog
from datetime import datetime
from typing import Any

logger = structlog.get_logger()


class PolicyEngine:
    def __init__(self, policy: dict | None = None):
        self.policy = policy or self._default_policy()

    @staticmethod
    def _default_policy() -> dict:
        return {
            "scope_allowlist": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
            "scope_denylist": [],
            "action_allowlist": [
                "arp_scan", "ping_sweep", "port_scan", "service_detection",
                "http_check", "tls_check", "ssh_check", "dns_check",
                "mdns_discovery", "ssdp_discovery", "upnp_check",
            ],
            "rate_limits": {"scan": "100/min", "check": "50/min"},
            "time_windows": {"allowed_hours": "00:00-23:59"},
        }

    def check_scope(self, target: str) -> bool:
        import ipaddress
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            return False

        for denied in self.policy.get("scope_denylist", []):
            try:
                if target_ip in ipaddress.ip_network(denied, strict=False):
                    logger.warning("Target in denylist", target=target, network=denied)
                    return False
            except ValueError:
                continue

        allowlist = self.policy.get("scope_allowlist", [])
        if not allowlist:
            return True

        for allowed in allowlist:
            try:
                if target_ip in ipaddress.ip_network(allowed, strict=False):
                    return True
            except ValueError:
                continue

        logger.warning("Target not in allowlist", target=target)
        return False

    def check_action(self, action: str) -> bool:
        allowlist = self.policy.get("action_allowlist", [])
        if not allowlist:
            return True
        return action in allowlist

    def check_time_window(self) -> bool:
        window = self.policy.get("time_windows", {}).get("allowed_hours", "00:00-23:59")
        try:
            start_str, end_str = window.split("-")
            start_h, start_m = map(int, start_str.split(":"))
            end_h, end_m = map(int, end_str.split(":"))
            now = datetime.now()
            current_minutes = now.hour * 60 + now.minute
            start_minutes = start_h * 60 + start_m
            end_minutes = end_h * 60 + end_m
            if start_minutes <= end_minutes:
                return start_minutes <= current_minutes <= end_minutes
            else:
                return current_minutes >= start_minutes or current_minutes <= end_minutes
        except (ValueError, AttributeError):
            return True

    def authorize(self, action: str, target: str) -> dict:
        results = {
            "allowed": True,
            "checks": {},
        }

        scope_ok = self.check_scope(target)
        results["checks"]["scope"] = scope_ok

        action_ok = self.check_action(action)
        results["checks"]["action"] = action_ok

        time_ok = self.check_time_window()
        results["checks"]["time_window"] = time_ok

        results["allowed"] = scope_ok and action_ok and time_ok

        if not results["allowed"]:
            logger.warning("Action denied", action=action, target=target, checks=results["checks"])

        return results
