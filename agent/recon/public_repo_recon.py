from __future__ import annotations

from agent.report.json_writer import write_json


def run_public_repo_recon(config: dict[str, object], output_path: str = "outputs/recon/public_repo_recon.json") -> dict[str, object]:
    recon = config.get("recon", {}) if isinstance(config.get("recon"), dict) else {}
    keywords = recon.get("public_repo_keywords", [])
    if not keywords:
        result = {"status": "skipped", "reason": "no user-provided public_repo_keywords configured", "results": []}
        write_json(output_path, result)
        return result
    result = {
        "status": "skipped",
        "reason": "passive placeholder only; configure a GitHub token/search integration before use",
        "keywords": [str(item) for item in keywords if item],
        "results": [],
    }
    write_json(output_path, result)
    return result
