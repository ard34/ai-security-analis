from __future__ import annotations

import ipaddress


def parse_a_aaaa(records: dict[str, list[str]]) -> dict[str, list[str]]:
    parsed = {"A": [], "AAAA": []}
    for record_type in ("A", "AAAA"):
        for value in records.get(record_type, []):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if record_type == "A" and ip.version == 4:
                parsed["A"].append(str(ip))
            if record_type == "AAAA" and ip.version == 6:
                parsed["AAAA"].append(str(ip))
    return parsed

