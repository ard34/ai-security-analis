from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.core.domain_input_normalizer import normalize_domain_input


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    plain = normalize_domain_input("fahram.dev")
    check(plain["root_domain"] == "fahram.dev", "plain root domain")
    check(plain["subdomain_recon_enabled"] is True, "plain subdomain recon")

    https = normalize_domain_input("https://fahram.dev")
    check(https["root_domain"] == "fahram.dev", "https root domain")

    www_path = normalize_domain_input("https://www.fahram.dev/login")
    check(www_path["hostname"] == "www.fahram.dev", "www hostname preserved")
    check(www_path["root_domain"] == "fahram.dev", "www root domain")
    check(www_path["target_domain"] == "fahram.dev", "www target domain")

    app = normalize_domain_input("app.fahram.dev")
    check(app["hostname"] == "app.fahram.dev", "app hostname preserved")
    check(app["root_domain"] == "fahram.dev", "app root domain")
    check(app["target_domain"] == "fahram.dev", "app target domain")

    ip = normalize_domain_input("http://127.0.0.1:3000")
    check(ip["target_type"] == "ip", "ip target type")
    check(ip["subdomain_recon_enabled"] is False, "ip subdomain recon disabled")

    localhost = normalize_domain_input("http://localhost:3000")
    check(localhost["target_type"] == "localhost", "localhost target type")
    check(localhost["subdomain_recon_enabled"] is False, "localhost subdomain recon disabled")

    try:
        normalize_domain_input("invalid input with spaces")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid input with spaces rejected")

    print("domain_input_normalizer tests passed")


if __name__ == "__main__":
    main()
