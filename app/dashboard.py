from __future__ import annotations

from ui.app import can_enable_domain_mode, mode_options, render_streamlit


def dashboard_modes() -> list[str]:
    return mode_options()


def domain_mode_enabled(assessment, confirmed: bool) -> bool:
    return can_enable_domain_mode(assessment, confirmed)


if __name__ == "__main__":
    render_streamlit()

