from __future__ import annotations

from core.assessment import Assessment
from core.pipeline_source import run_source_assessment


def mode_options() -> list[str]:
    return ["Type 1 Source Folder", "Type 2 Domain"]


def can_enable_domain_mode(assessment: Assessment | None, confirmed: bool) -> bool:
    return bool(assessment and assessment.approved and confirmed)


def render_streamlit() -> None:
    try:
        import streamlit as st
    except ImportError:
        return

    st.title("AI Security Analyst")
    mode = st.selectbox("Mode", mode_options())
    if mode == "Type 1 Source Folder":
        source_path = st.text_input("Local folder path")
        if st.button("Run source assessment") and source_path:
            result = run_source_assessment(source_path)
            st.json(result.to_dict())
    else:
        st.checkbox("I confirm this is an authorized safe-live assessment", key="safe_live_confirm")
        st.info("Domain scans require an approved assessment JSON through the CLI or local helper.")


if __name__ == "__main__":
    render_streamlit()

