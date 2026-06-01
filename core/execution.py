from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.request import Request, urlopen

from core.logging import AuditLogger
from core.policies import DomainRunPolicy, PolicyViolation, require_domain_run_policy, require_safe_http_method, sanitize_headers


@dataclass(slots=True)
class ExecutionEngine:
    policy: DomainRunPolicy
    assessment_approved: bool
    audit: AuditLogger
    killed: bool = False
    used_budget: int = 0
    _last_action_at: float = field(default=0.0)

    def __post_init__(self) -> None:
        require_domain_run_policy(self.policy, assessment_approved=self.assessment_approved)

    def kill(self) -> None:
        self.killed = True
        self.audit.event("kill_switch_enabled")

    def _guard(self, action: str) -> None:
        if self.killed:
            raise PolicyViolation("kill switch is enabled")
        if self.used_budget >= self.policy.scan_budget:
            raise PolicyViolation("scan budget exhausted")
        elapsed = time.monotonic() - self._last_action_at
        minimum_gap = 1.0 / self.policy.rate_limit_per_second
        if self._last_action_at and elapsed < minimum_gap:
            time.sleep(minimum_gap - elapsed)
        self.used_budget += 1
        self._last_action_at = time.monotonic()
        self.audit.event("guarded_live_action", live_action=action, used_budget=self.used_budget)

    def guarded_call(self, action: str, fn: Callable[[], object]) -> object:
        self._guard(action)
        return fn()

    def http_request(self, url: str, *, method: str = "GET") -> dict[str, object]:
        method = require_safe_http_method(method)

        def perform() -> dict[str, object]:
            request = Request(url, method=method, headers={"User-Agent": "ai-security-analyst-safe-passive/1.0"})
            with urlopen(request, timeout=self.policy.timeout_seconds) as response:
                headers = sanitize_headers(dict(response.headers.items()))
                body = b"" if method == "HEAD" else response.read(200_000)
                return {
                    "url": url,
                    "method": method,
                    "status": response.status,
                    "headers": headers,
                    "body": body.decode("utf-8", errors="replace"),
                }

        return self.guarded_call(f"http_{method.lower()}", perform)  # type: ignore[return-value]

    def dns_a_aaaa(self, host: str) -> dict[str, list[str]]:
        def perform() -> dict[str, list[str]]:
            records = {"A": [], "AAAA": []}
            for family, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
                try:
                    answers = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
                except socket.gaierror:
                    continue
                for answer in answers:
                    address = answer[4][0]
                    if address not in records[label]:
                        records[label].append(address)
            return records

        return self.guarded_call("dns_a_aaaa", perform)  # type: ignore[return-value]
