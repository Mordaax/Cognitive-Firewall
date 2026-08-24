"""Streamlit dashboard using the authenticated API only."""

import os

import httpx


def sanitize_dashboard_data(raw: dict) -> dict:
    """Defense in depth: pass only aggregate fields into Streamlit widgets."""
    allowed = ("total", "blocked", "sanitized", "allowed", "approvals", "policy_versions")
    result = {key: raw.get(key) for key in allowed}
    agent_fields = ("agent_id", "total", "blocked", "sanitized", "allowed", "approvals",
                    "mean_injection_score", "mean_privacy_score")
    result["agents"] = [{key: agent.get(key) for key in agent_fields} for agent in raw.get("agents", [])]
    return result


def main() -> None:
    import streamlit as st

    st.set_page_config(page_title="Cognitive Firewall", layout="wide")
    st.title("Cognitive Firewall")
    base_url = os.environ.get("FIREWALL_API_URL", "http://127.0.0.1:8000")
    token = os.environ.get("FIREWALL_OPERATOR_TOKEN", "")
    if not token:
        st.error("Operator credential is not configured")
        st.stop()
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/v1/reports/summary",
                             headers={"Authorization": f"Bearer {token}"}, timeout=5)
        response.raise_for_status()
        data = sanitize_dashboard_data(response.json())
    except (httpx.HTTPError, ValueError):
        st.error("Telemetry is unavailable")
        st.stop()
    columns = st.columns(4)
    for column, key in zip(columns, ("total", "blocked", "sanitized", "allowed")):
        column.metric(key.title(), data[key] or 0)
    st.caption("Policy versions: " + ", ".join(data.get("policy_versions") or []))
    if data["agents"]:
        st.subheader("Agent risk")
        st.dataframe(data["agents"], hide_index=True)
        st.bar_chart({agent["agent_id"]: agent["blocked"] for agent in data["agents"]})


if __name__ == "__main__":
    main()
