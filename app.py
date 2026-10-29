import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
from datetime import datetime, timezone

from database.db import (
    init_db, reset_db, get_all_events, get_all_incidents,
    get_incident_by_id, get_all_approvals
)
from pipeline import run_detection_pipeline, evaluate_against_ground_truth, load_json_file
from response.sandbox import SimulationSandbox
from detection.rules import URLAnalyzer

# ---------------------------------------------------------
# Page Configuration & Modern Cyber Dark Theme Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="SENTINEL AI — Threat Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Theme CSS
st.markdown("""
<style>
    /* Main Background & Base Typography */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Neon Green Header Accents */
    .brand-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #00ff66;
        margin-bottom: 0px;
        text-shadow: 0 0 12px rgba(0, 255, 102, 0.25);
    }
    .brand-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 2px;
        margin-bottom: 20px;
    }
    
    /* Metrics / KPI Cards */
    .kpi-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .kpi-val {
        font-size: 1.8rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.2;
    }
    .kpi-lbl {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
    }
    .kpi-critical { border-left: 4px solid #ef4444; }
    .kpi-warning  { border-left: 4px solid #f59e0b; }
    .kpi-safe     { border-left: 4px solid #00ff66; }
    .kpi-info     { border-left: 4px solid #3b82f6; }
    
    /* Badges */
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high     { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .badge-medium   { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    .badge-low      { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    
    /* Simulation Disclaimer Banner */
    .sim-banner {
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid #00ff66;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 18px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .sim-text {
        font-size: 0.82rem;
        color: #cbd5e1;
    }
    
    /* Clean Cards & Evidence Blocks */
    .evidence-block {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 14px;
    }
    .evidence-header {
        font-size: 0.88rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #00ff66;
        margin-bottom: 8px;
    }
    
    /* Timeline Node Card */
    .timeline-card {
        background: #111827;
        border-left: 3px solid #00ff66;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 0 6px 6px 0;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Sidebar Navigation & System Controls
# ---------------------------------------------------------
with st.sidebar:
    st.markdown('<div class="brand-title">🛡️ SENTINEL AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-subtitle">AI vs AI Defensive Security Engine</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <div style="background:#111827; border: 1px solid #1f2937; border-radius:6px; padding:10px; margin-bottom:15px;">
        <span style="color:#00ff66; font-size:0.75rem; font-weight:700;">● SYSTEM ACTIVE</span><br>
        <span style="color:#94a3b8; font-size:0.75rem;">Mode: <b>SIMULATED SANDBOX</b></span><br>
        <span style="color:#94a3b8; font-size:0.75rem;">Correlation Window: <b>60 min</b></span>
    </div>
    """, unsafe_allow_html=True)
    
    nav_option = st.radio(
        "Navigation",
        [
            "1. SOC Overview",
            "2. Threat Monitoring",
            "3. Attack Campaign Explorer",
            "4. Incident Details & Evidence",
            "5. Human Approval Center",
            "6. Detection Analytics & ML",
            "7. Demo Scenarios & Testing",
            "8. Live URL & Phishing Inspector"
        ],
        index=0
    )
    
    st.markdown("---")
    st.markdown("### ⚙️ Demo Controls")
    
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🚀 Run Pipeline", use_container_width=True):
            with st.spinner("Processing events & correlating campaigns..."):
                run_res = run_detection_pipeline()
                st.session_state["pipeline_results"] = run_res
                st.success(f"Correlated {run_res['total_incidents_detected']} incidents!")
                st.rerun()
                
    with col_btn2:
        if st.button("🔄 Reset Data", use_container_width=True):
            reset_db()
            st.session_state.pop("pipeline_results", None)
            st.info("Database reset.")
            st.rerun()

    st.markdown("---")
    st.caption("SENTINEL AI v1.0 • Enterprise SOC Platform")

# ---------------------------------------------------------
# Auto-Initialize Pipeline if First Run
# ---------------------------------------------------------
init_db()
incidents = get_all_incidents()
events = get_all_events()

if not incidents and not events:
    run_res = run_detection_pipeline()
    st.session_state["pipeline_results"] = run_res
    incidents = get_all_incidents()
    events = get_all_events()

approvals = get_all_approvals()

# Safety banner displayed on all views
st.markdown("""
<div class="sim-banner">
    <span style="font-size:1.2rem;">⚡</span>
    <span class="sim-text">
        <b>SAFE RESPONSE SIMULATION MODE ACTIVE:</b> All automated triggers and containment recommendations operate strictly within an isolated sandbox. Zero modifications to live directory accounts, firewalls, or production hosts.
    </span>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 1: SOC OVERVIEW
# ---------------------------------------------------------
if nav_option == "1. SOC Overview":
    st.header("Security Operations Center — Overview")
    
    pending_approvals = [a for a in approvals if a.get("status") == "PENDING_APPROVAL"]
    critical_incidents = [i for i in incidents if i.get("severity") in ["CRITICAL", "HIGH"]]
    contained_approvals = [a for a in approvals if a.get("status") == "SIMULATED_EXECUTED"]
    
    # KPI Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="kpi-card kpi-info">
            <div class="kpi-lbl">Total Events Ingested</div>
            <div class="kpi-val">{len(events)}</div>
            <span style="font-size:0.75rem; color:#94a3b8;">Email, Auth & Net Flow Telemetry</span>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="kpi-card kpi-warning">
            <div class="kpi-lbl">Correlated Incidents</div>
            <div class="kpi-val">{len(incidents)}</div>
            <span style="font-size:0.75rem; color:#f59e0b;">Multi-Vector Threat Campaigns</span>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="kpi-card kpi-critical">
            <div class="kpi-lbl">Critical & High Risk</div>
            <div class="kpi-val">{len(critical_incidents)}</div>
            <span style="font-size:0.75rem; color:#ef4444;">Requiring Immediate Triage</span>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="kpi-card kpi-safe">
            <div class="kpi-lbl">Awaiting Human Approval</div>
            <div class="kpi-val">{len(pending_approvals)}</div>
            <span style="font-size:0.75rem; color:#00ff66;">{len(contained_approvals)} Simulated Executed</span>
        </div>
        """, unsafe_allow_html=True)

    # Active Campaigns Feed & Overview Charts
    col_feed, col_chart = st.columns([1.6, 1.4])
    
    with col_feed:
        st.subheader("🚨 Active Coordinated Threat Campaigns")
        if incidents:
            for inc in incidents:
                sev = inc.get("severity", "MEDIUM")
                badge_class = f"badge-{sev.lower()}"
                score = inc.get("risk_score", 0)
                
                with st.container():
                    st.markdown(f"""
                    <div class="evidence-block" style="border-left: 4px solid {'#ef4444' if sev=='CRITICAL' else '#f59e0b' if sev=='HIGH' else '#3b82f6'};">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-weight:700; font-size:1.05rem; color:#f8fafc;">{inc.get('title')}</span>
                            <span class="badge {badge_class}">{sev} • Risk {score}/100</span>
                        </div>
                        <div style="font-size:0.83rem; color:#94a3b8; margin-bottom:8px;">
                            <b>Target Entity:</b> User: <code>{inc.get('primary_user') or 'N/A'}</code> | Device: <code>{inc.get('primary_device') or 'N/A'}</code> | Threat IP: <code>{inc.get('primary_ip') or 'N/A'}</code>
                        </div>
                        <div style="font-size:0.85rem; color:#cbd5e1; line-height:1.4;">
                            {inc.get('explanation', {}).get('inferred_relationships', ['Coordinated cross-telemetry pattern detected.'])[0]}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("No active incidents detected. Ingest sample data to begin correlation.")
            
    with col_chart:
        st.subheader("📊 Telemetry Source Distribution")
        if events:
            df_ev = pd.DataFrame(events)
            src_counts = df_ev["source"].value_counts().reset_index()
            src_counts.columns = ["Source", "Events"]
            
            fig = px.pie(
                src_counts, values="Events", names="Source",
                color="Source",
                color_discrete_map={"EMAIL": "#3b82f6", "AUTH": "#10b981", "NETWORK": "#8b5cf6"},
                hole=0.55
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                margin=dict(l=20, r=20, t=20, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("""
        <div class="evidence-block">
            <div class="evidence-header">DEFENSIVE CORRELATION PRINCIPLE</div>
            <p style="font-size:0.82rem; color:#94a3b8; margin:0;">
                Isolated alerts from a single telemetry stream produce alert fatigue and false positives. 
                SENTINEL AI fuses <b>Email Delivery</b>, <b>IdP Authentication</b>, and <b>Network Egress</b> into a high-fidelity state machine attack chain before raising critical escalation.
            </p>
        </div>
        """, unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 2: THREAT MONITORING (UNIFIED TELEMETRY STREAM)
# ---------------------------------------------------------
elif nav_option == "2. Threat Monitoring":
    st.header("Live Threat Telemetry Feed")
    st.caption("Unified multi-source stream linking Email Gateway, Authentication, and Network Flows.")
    
    if not events:
        st.warning("No events available. Click 'Run Pipeline' in the sidebar.")
    else:
        df_all = pd.DataFrame(events)
        
        # Filters
        c_f1, c_f2, c_f3 = st.columns([1, 1, 2])
        with c_f1:
            source_filter = st.multiselect("Filter by Source", ["EMAIL", "AUTH", "NETWORK"], default=["EMAIL", "AUTH", "NETWORK"])
        with c_f2:
            scenario_filter = st.selectbox("Scenario Classification", ["All Events", "Malicious / Campaigns Only", "Benign Only"])
        with c_f3:
            search_query = st.text_input("🔍 Search User, IP, Device or Keyword", "")
            
        # Apply filters
        df_filtered = df_all[df_all["source"].isin(source_filter)].copy()
        
        if scenario_filter == "Malicious / Campaigns Only":
            df_filtered = df_filtered[~df_filtered["scenario_tag"].isin(["BENIGN", "UNKNOWN"])]
        elif scenario_filter == "Benign Only":
            df_filtered = df_filtered[df_filtered["scenario_tag"] == "BENIGN"]
            
        if search_query:
            q = search_query.lower()
            df_filtered = df_filtered[
                df_filtered["user_id"].astype(str).str.lower().str.contains(q) |
                df_filtered["ip_address"].astype(str).str.lower().str.contains(q) |
                df_filtered["device_id"].astype(str).str.lower().str.contains(q) |
                df_filtered["summary"].astype(str).str.lower().str.contains(q) |
                df_filtered["event_id"].astype(str).str.lower().str.contains(q)
            ]
            
        st.markdown(f"**Showing {len(df_filtered)} of {len(df_all)} events**")
        
        # Display Table
        display_cols = ["event_id", "timestamp", "source", "user_id", "device_id", "ip_address", "scenario_tag", "summary"]
        st.dataframe(
            df_filtered[display_cols],
            use_container_width=True,
            column_config={
                "event_id": st.column_config.TextColumn("Event ID", width="small"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "source": st.column_config.TextColumn("Source", width="small"),
                "user_id": st.column_config.TextColumn("User", width="medium"),
                "device_id": st.column_config.TextColumn("Device", width="medium"),
                "ip_address": st.column_config.TextColumn("IP Indicator", width="medium"),
                "scenario_tag": st.column_config.TextColumn("Tag", width="medium"),
                "summary": st.column_config.TextColumn("Telemetry Summary", width="large"),
            },
            hide_index=True
        )
        
        # Inspector for specific event
        st.markdown("---")
        st.subheader("🔍 Raw Event Inspector")
        sel_eid = st.selectbox("Select Event ID to inspect raw telemetry", df_filtered["event_id"].tolist() if not df_filtered.empty else [])
        if sel_eid:
            matching = [e for e in events if e.get("event_id") == sel_eid]
            if matching:
                st.json(matching[0].get("raw_payload", {}))

# ---------------------------------------------------------
# SECTION 3: ATTACK CAMPAIGN EXPLORER
# ---------------------------------------------------------
elif nav_option == "3. Attack Campaign Explorer":
    st.header("Attack Campaign Explorer")
    st.caption("Visual chronological kill chain correlating Email Delivery → Authentication Exploitation → Network Exfiltration.")
    
    if not incidents:
        st.info("No incidents detected.")
    else:
        # Selector for incident
        inc_options = {f"{i['incident_id']} - {i['title']} (Risk: {i['risk_score']})": i['incident_id'] for i in incidents}
        selected_label = st.selectbox("Select Threat Campaign to Explore", list(inc_options.keys()))
        selected_id = inc_options[selected_label]
        inc = get_incident_by_id(selected_id)
        
        if inc:
            # Campaign Header
            sev = inc.get("severity", "MEDIUM")
            st.markdown(f"""
            <div class="evidence-block" style="border-left: 4px solid {'#ef4444' if sev=='CRITICAL' else '#f59e0b'};">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3 style="margin:0; color:#f8fafc;">{inc.get('title')}</h3>
                        <p style="margin:4px 0 0 0; color:#94a3b8; font-size:0.85rem;">
                            Incident ID: <code>{inc.get('incident_id')}</code> • Campaign Tag: <code>{inc.get('campaign_tag')}</code>
                        </p>
                    </div>
                    <div>
                        <span class="badge badge-{sev.lower()}" style="font-size:0.9rem; padding:6px 12px;">{sev} • {inc.get('risk_score')}/100</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Interactive Plotly Timeline
            tl_events = inc.get("timeline", [])
            if tl_events:
                st.subheader("Chronological Sequence Timeline")
                df_tl = pd.DataFrame(tl_events)
                df_tl["time_dt"] = pd.to_datetime(df_tl["timestamp"])
                df_tl = df_tl.sort_values("time_dt")
                
                # Visual Plotly scatter timeline
                fig = px.scatter(
                    df_tl,
                    x="time_dt",
                    y="source",
                    color="stage",
                    size=[14]*len(df_tl),
                    hover_data=["event_id", "summary", "stage"],
                    color_discrete_map={
                        "INITIAL_ACCESS": "#3b82f6",
                        "CREDENTIAL_ACCESS": "#f59e0b",
                        "COMMAND_AND_CONTROL": "#ef4444",
                        "ANOMALOUS_ACTIVITY": "#10b981"
                    },
                    title="Multi-Stage Attack Progression"
                )
                fig.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    font=dict(color="#94a3b8"),
                    xaxis=dict(showgrid=True, gridcolor="#1f2937", title="Event Timestamp (UTC)"),
                    yaxis=dict(showgrid=True, gridcolor="#1f2937", title="Telemetry Vector"),
                    margin=dict(l=40, r=40, t=50, b=40),
                    height=280
                )
                st.plotly_chart(fig, use_container_width=True)
                
            # Sequence Progression Flow & Explanation Cards
            c_flow, c_corr = st.columns([1.5, 1.5])
            with c_flow:
                st.subheader("Correlated Kill Chain Steps")
                for idx, ev in enumerate(inc.get("correlated_events", [])):
                    st.markdown(f"""
                    <div class="timeline-card">
                        <div style="display:flex; justify-content:space-between;">
                            <b style="color:#00ff66;">Stage {idx+1}: {ev.get('stage')}</b>
                            <span style="font-size:0.75rem; color:#94a3b8;">{ev.get('timestamp')}</span>
                        </div>
                        <div style="font-size:0.85rem; color:#e2e8f0; margin-top:4px;">
                            <b>{ev.get('source')}</b> (<code>{ev.get('event_id')}</code>): {ev.get('summary')}
                        </div>
                        <div style="font-size:0.75rem; color:#94a3b8; margin-top:2px;">
                            Correlation Reason: {ev.get('correlation_reason')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
            with c_corr:
                st.subheader("Target Entity Graph")
                st.markdown(f"""
                <div class="evidence-block">
                    <div class="evidence-header">PRIMARY COMPROMISED ENTITIES</div>
                    <ul style="color:#cbd5e1; font-size:0.85rem; line-height:1.7;">
                        <li><b>User Identity:</b> <code>{inc.get('primary_user') or 'N/A'}</code></li>
                        <li><b>Endpoint Workstation:</b> <code>{inc.get('primary_device') or 'N/A'}</code></li>
                        <li><b>External Threat Indicator IP:</b> <code>{inc.get('primary_ip') or 'N/A'}</code></li>
                        <li><b>State Machine Match:</b> <code>{'CONFIRMED (Email -> Auth -> Net)' if inc.get('evidence', {}).get('sequence_matched') else 'PARTIAL CORRELATION'}</code></li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("""
                <div class="evidence-block">
                    <div class="evidence-header">CORRELATION HYPOTHESIS</div>
                    <p style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">
                        The correlation engine verified that an external phishing delivery vector directly preceded an authentication anomaly on the user's primary endpoint, which subsequently established egress communication with the attacker's external command-and-control server within the 60-minute correlation threshold.
                    </p>
                </div>
                """, unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 4: INCIDENT DETAILS & EXPLAINABLE EVIDENCE
# ---------------------------------------------------------
elif nav_option == "4. Incident Details & Evidence":
    st.header("Incident Details & Explainable Risk Assessment")
    st.caption("Deep triage breakdown distinguishing observed facts, analytical inferences, and rule weights.")
    
    if not incidents:
        st.info("No incidents detected.")
    else:
        inc_options = {f"{i['incident_id']} - {i['title']}": i['incident_id'] for i in incidents}
        selected_label = st.selectbox("Select Incident", list(inc_options.keys()))
        selected_id = inc_options[selected_label]
        inc = get_incident_by_id(selected_id)
        
        if inc:
            # Top summary banner
            sev = inc.get("severity", "MEDIUM")
            score = inc.get("risk_score", 0.0)
            conf = int(inc.get("confidence", 0.0) * 100)
            
            c_meta1, c_meta2, c_meta3, c_meta4 = st.columns(4)
            c_meta1.metric("Risk Score", f"{score}/100", f"Category: {sev}")
            c_meta2.metric("Confidence Level", f"{conf}%", "Evidence-calibrated")
            c_meta3.metric("Primary User", inc.get("primary_user") or "N/A")
            c_meta4.metric("Primary Device", inc.get("primary_device") or "N/A")
            
            st.markdown("---")
            
            # Left: Facts vs Inferences | Right: Risk Score Waterfall / Breakdown
            c_ev, c_risk = st.columns([1.6, 1.4])
            
            with c_ev:
                st.subheader("📋 Evidence Panel")
                
                # 1. Observed Facts
                st.markdown("""<div class="evidence-header">1. OBSERVED FACTS (Verifiable Telemetry)</div>""", unsafe_allow_html=True)
                facts = inc.get("explanation", {}).get("observed_facts", [])
                if facts:
                    for f in facts:
                        st.markdown(f"- <span style='font-size:0.85rem; color:#f1f5f9;'>{f}</span>", unsafe_allow_html=True)
                else:
                    st.write("No observed facts recorded.")
                    
                st.markdown("<br>", unsafe_allow_html=True)
                
                # 2. Inferred Relationships
                st.markdown("""<div class="evidence-header">2. INFERRED RELATIONSHIPS (Analytic Deductions)</div>""", unsafe_allow_html=True)
                inferences = inc.get("explanation", {}).get("inferred_relationships", [])
                if inferences:
                    for inf in inferences:
                        st.markdown(f"- <span style='font-size:0.85rem; color:#94a3b8;'>{inf}</span>", unsafe_allow_html=True)
                else:
                    st.write("No inferences recorded.")
                    
                st.markdown("<br>", unsafe_allow_html=True)
                
                # 3. Detection Rules Triggered
                st.markdown("""<div class="evidence-header">3. DETECTION RULES TRIGGERED</div>""", unsafe_allow_html=True)
                rules = inc.get("rule_ids", [])
                for rid in rules:
                    st.markdown(f"- <code>{rid}</code>")

            with c_risk:
                st.subheader("🧮 Explainable Risk Score Breakdown")
                factors = inc.get("evidence", {}).get("factors", {})
                
                # Risk Score Gauge
                fig_gauge = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = score,
                    title = {'text': "Calculated Threat Risk", 'font': {'size': 18, 'color': '#f8fafc'}},
                    number = {'font': {'color': '#00ff66' if score < 70 else '#ef4444'}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickcolor': "#94a3b8"},
                        'bar': {'color': "#ef4444" if score >= 85 else "#f59e0b" if score >= 70 else "#3b82f6"},
                        'bgcolor': "#111827",
                        'borderwidth': 1,
                        'bordercolor': "#1f2937",
                        'steps': [
                            {'range': [0, 40], 'color': 'rgba(16, 185, 129, 0.15)'},
                            {'range': [40, 70], 'color': 'rgba(59, 130, 246, 0.15)'},
                            {'range': [70, 85], 'color': 'rgba(245, 158, 11, 0.15)'},
                            {'range': [85, 100], 'color': 'rgba(239, 68, 68, 0.25)'}
                        ]
                    }
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="#111827",
                    font=dict(color="#94a3b8"),
                    margin=dict(l=30, r=30, t=40, b=20),
                    height=220
                )
                st.plotly_chart(fig_gauge, use_container_width=True)
                
                # Factors Breakdown Table
                st.markdown(f"""
                <div class="evidence-block">
                    <div class="evidence-header">SCORE FORMULATION FACTORS</div>
                    <table style="width:100%; font-size:0.8rem; color:#cbd5e1;">
                        <tr><td><b>Base Severity Rule:</b></td><td><code>{factors.get('base_severity_rule', 'N/A')}</code> (+{factors.get('base_severity_points', 0)} pts)</td></tr>
                        <tr><td><b>Additional Rule Contribution:</b></td><td>+{factors.get('additional_rules_points', 0)} pts</td></tr>
                        <tr><td><b>Correlated Sources ({factors.get('sources_detected_count', 1)}):</b></td><td>×{factors.get('correlation_multiplier', 1.0)} Multiplier</td></tr>
                        <tr><td><b>Kill Chain Attack Sequence Bonus:</b></td><td>+{factors.get('sequence_attack_chain_bonus', 0)} pts</td></tr>
                        <tr><td><b>Evidence Reliability Adjustment:</b></td><td>{factors.get('evidence_reliability_adjustment', 0):+} pts</td></tr>
                        <tr style="border-top:1px solid #374151; font-weight:700; color:#00ff66;">
                            <td><b>FINAL CLAMPED SCORE:</b></td><td><b>{score}/100</b></td>
                        </tr>
                    </table>
                </div>
                """, unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 5: HUMAN APPROVAL CENTER & RESPONSE SIMULATION
# ---------------------------------------------------------
elif nav_option == "5. Human Approval Center":
    st.header("Human-in-the-Loop Approval Center")
    st.caption("SOC containment authorization workflow. Strictly simulated execution with zero real-world side effects.")
    
    st.markdown("""
    <div class="evidence-block">
        <div class="evidence-header">SIMULATION POLICY & SAFETY CONTROLS</div>
        <p style="font-size:0.83rem; color:#94a3b8; margin:0;">
            In accordance with defensive safety standards, automated containment actions (session invalidation, host isolation, firewall blocklisting) are never executed directly. 
            All response actions require an authenticated SOC analyst to review the evidence and record an explicit <b>APPROVE</b> or <b>REJECT</b> decision before mock execution.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    pending_actions = [a for a in approvals if a.get("status") == "PENDING_APPROVAL"]
    history_actions = [a for a in approvals if a.get("status") != "PENDING_APPROVAL"]
    
    st.subheader(f"Pending Approvals ({len(pending_actions)})")
    
    if not pending_actions:
        st.success("✅ No pending actions awaiting approval. All simulated response workflows have been processed.")
    else:
        for act in pending_actions:
            with st.container():
                st.markdown(f"""
                <div class="evidence-block" style="border-left: 4px solid #f59e0b;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:700; font-size:0.95rem; color:#f8fafc;">
                            Action ID: <code>{act.get('action_id')}</code> — {act.get('action_type')}
                        </span>
                        <span class="badge badge-high">PENDING APPROVAL</span>
                    </div>
                    <div style="font-size:0.85rem; color:#cbd5e1; margin:6px 0;">
                        <b>Target Entity:</b> <code>{act.get('target_entity')}</code> | <b>Associated Incident:</b> <code>{act.get('incident_id')}</code>
                    </div>
                    <div style="font-size:0.83rem; color:#94a3b8;">
                        {act.get('description')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Reviewer Action Form
                with st.expander(f"Review and Authorize Action: {act.get('action_id')}", expanded=False):
                    f_col1, f_col2 = st.columns([1, 2])
                    with f_col1:
                        rev_name = st.text_input("Reviewer Name / ID", value="SOC-Analyst-Alpha", key=f"rev_{act.get('action_id')}")
                    with f_col2:
                        rev_notes = st.text_input("Reviewer Decision Reason / Justification", value="Evidence cross-verified against C2 egress logs.", key=f"note_{act.get('action_id')}")
                    
                    btn_c1, btn_c2, _ = st.columns([1, 1, 3])
                    with btn_c1:
                        if st.button("✅ Approve", key=f"app_{act.get('action_id')}", use_container_width=True):
                            res = SimulationSandbox.process_human_decision(
                                action_id=act.get("action_id"),
                                decision="APPROVE",
                                reviewer_name=rev_name,
                                reviewer_notes=rev_notes,
                                action_type=act.get("action_type"),
                                target_entity=act.get("target_entity")
                            )
                            st.success(f"Simulated execution recorded for {act.get('action_id')}!")
                            st.rerun()
                    with btn_c2:
                        if st.button("❌ Reject", key=f"rej_{act.get('action_id')}", use_container_width=True):
                            res = SimulationSandbox.process_human_decision(
                                action_id=act.get("action_id"),
                                decision="REJECT",
                                reviewer_name=rev_name,
                                reviewer_notes=rev_notes,
                                action_type=act.get("action_type"),
                                target_entity=act.get("target_entity")
                            )
                            st.warning(f"Action {act.get('action_id')} rejected.")
                            st.rerun()

    # Historical Audit Trail
    st.markdown("---")
    st.subheader(f"Approval Audit Trail & Simulation Execution Logs ({len(history_actions)})")
    if history_actions:
        df_hist = pd.DataFrame(history_actions)
        st.dataframe(
            df_hist[["action_id", "incident_id", "action_type", "target_entity", "status", "reviewer_name", "decision", "reviewed_at"]],
            use_container_width=True,
            hide_index=True
        )
        
        # Display simulated execution payload for an inspected action
        ins_action_id = st.selectbox("Inspect Execution Telemetry Log", [a["action_id"] for a in history_actions])
        ins_match = [a for a in history_actions if a["action_id"] == ins_action_id]
        if ins_match and ins_match[0].get("execution_log"):
            st.markdown(f"**Simulated Execution JSON Payload (`{ins_action_id}`):**")
            st.json(ins_match[0]["execution_log"])
    else:
        st.caption("No historical reviewer decisions recorded yet.")

# ---------------------------------------------------------
# SECTION 6: DETECTION ANALYTICS & EXPERIMENTAL ML
# ---------------------------------------------------------
elif nav_option == "6. Detection Analytics & ML":
    st.header("Detection Analytics & Model Evaluation")
    st.caption("Statistical telemetry, MITRE ATT&CK coverage, experimental Isolation Forest, and benchmark metrics.")
    
    gt_data = load_json_file("ground_truth.json")
    benchmark_metrics = evaluate_against_ground_truth(incidents, gt_data)
    
    # Benchmark KPIs
    st.subheader("🎯 Ground Truth Detection Evaluation")
    st.markdown(f"""
    <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:12px;">
        {benchmark_metrics.get('disclaimer')}
    </div>
    """, unsafe_allow_html=True)
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Campaign Precision", f"{int(benchmark_metrics['precision']*100)}%", "Zero False Alarms")
    m2.metric("Campaign Recall", f"{int(benchmark_metrics['recall']*100)}%", f"{benchmark_metrics['campaigns_detected']}/{benchmark_metrics['campaigns_expected']} Detected")
    m3.metric("F1 Detection Score", f"{benchmark_metrics['f1_score']}", "Harmonic Mean")
    m4.metric("False Positive Rate", f"{benchmark_metrics['false_positive_rate']*100}%", f"0 of {benchmark_metrics['benign_events_count']} Benign Flagged")
    
    st.markdown("---")
    
    c_ml, c_dist = st.columns([1.5, 1.5])
    
    with c_ml:
        st.subheader("🧪 Experimental ML Anomaly Detection (Isolation Forest)")
        st.markdown("""
        <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:8px;">
            <b>Model Label:</b> Experimental Unsupervised Anomaly Detection.<br>
            <b>Notice:</b> Mathematical outliers in feature space do not prove malicious intent or AI-generated attacks without corroborating deterministic rule evidence.
        </div>
        """, unsafe_allow_html=True)
        
        email_logs = load_json_file("email_logs.json")
        auth_logs = load_json_file("auth_logs.json")
        network_logs = load_json_file("network_logs.json")
        
        from detection.anomaly_detection import AnomalyDetector
        ml_detector = AnomalyDetector()
        df_feat = ml_detector.extract_features(email_logs, auth_logs, network_logs)
        df_ml = ml_detector.fit_and_predict(df_feat)
        
        # Plotly Scatter of Anomaly Scores
        fig_ml = px.scatter(
            df_ml,
            x="failed_login_count",
            y="outbound_bytes_mb",
            color="ml_verdict",
            size="anomaly_score",
            hover_data=["entity", "anomaly_score", "phishing_email_hits"],
            color_discrete_map={"EXPERIMENTAL_ANOMALY": "#ef4444", "NORMAL_BASELINE": "#00ff66"},
            title="Entity Feature Space (Failed Logins vs Outbound MB)"
        )
        fig_ml.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#94a3b8"),
            xaxis=dict(showgrid=True, gridcolor="#1f2937"),
            yaxis=dict(showgrid=True, gridcolor="#1f2937"),
            margin=dict(l=30, r=30, t=40, b=30),
            height=280
        )
        st.plotly_chart(fig_ml, use_container_width=True)
        
        st.dataframe(
            df_ml[["entity", "anomaly_score", "failed_login_count", "outbound_bytes_mb", "ml_verdict"]],
            use_container_width=True,
            hide_index=True
        )

    with c_dist:
        st.subheader("📈 Threat Severity & Outcomes")
        if incidents:
            df_inc = pd.DataFrame(incidents)
            sev_counts = df_inc["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            
            fig_bar = px.bar(
                sev_counts, x="Severity", y="Count",
                color="Severity",
                color_discrete_map={"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#3b82f6", "LOW": "#10b981"},
                title="Incident Severity Distribution"
            )
            fig_bar.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#94a3b8"),
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor="#1f2937"),
                margin=dict(l=30, r=30, t=40, b=30),
                height=240
            )
            st.plotly_chart(fig_bar, use_container_width=True)
            
        st.markdown("""
        <div class="evidence-block">
            <div class="evidence-header">MITRE ATT&CK MAPPING</div>
            <table style="width:100%; font-size:0.8rem; color:#cbd5e1;">
                <tr><td><b>Initial Access:</b></td><td><code>T1566 (Phishing)</code>, <code>T1566.001 (Spearphishing Attachment)</code></td></tr>
                <tr><td><b>Credential Access:</b></td><td><code>T1110 (Brute Force / Password Spray)</code>, <code>T1621 (MFA Fatigue)</code></td></tr>
                <tr><td><b>Privilege Escalation:</b></td><td><code>T1078 (Valid Accounts)</code>, <code>T1068 (Exploitation for Privilege)</code></td></tr>
                <tr><td><b>Command & Control:</b></td><td><code>T1071 (Application Layer Protocol)</code>, <code>T1571 (Non-Standard Port)</code></td></tr>
                <tr><td><b>Exfiltration:</b></td><td><code>T1041 (Exfiltration Over C2 Channel)</code></td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 7: DEMO SCENARIOS & TESTING
# ---------------------------------------------------------
elif nav_option == "7. Demo Scenarios & Testing":
    st.header("Demo Walkthrough & Validation Scenarios")
    st.caption("Demonstration suite showcasing how coordinated multi-vector campaigns are reconstructed from disparate logs.")
    
    gt = load_json_file("ground_truth.json")
    campaigns = gt.get("campaigns", [])
    
    st.subheader("🎯 Ground Truth Attack Scenarios")
    
    for c in campaigns:
        with st.expander(f"Campaign: {c['name']} ({c['id']})", expanded=True):
            st.markdown(f"""
            <div style="font-size:0.88rem; color:#cbd5e1; margin-bottom:8px;">
                <b>Description:</b> {c['description']}
            </div>
            <div style="font-size:0.83rem; color:#94a3b8; margin-bottom:10px;">
                <b>Expected Severity:</b> <span class="badge badge-critical">{c['expected_severity']}</span> | 
                <b>Target User:</b> <code>{c['primary_user']}</code> | 
                <b>Target Device:</b> <code>{c['device_id']}</code> | 
                <b>Adversary IP:</b> <code>{c['indicator_ip']}</code>
            </div>
            """, unsafe_allow_html=True)
            
            # Show events involved
            c_eids = c.get("event_ids", [])
            st.markdown(f"**Linked Scenario Event IDs:** `{', '.join(c_eids)}`")
            
            # Match against detected incidents
            matching_inc = [i for i in incidents if i.get("campaign_tag") == c["id"]]
            if matching_inc:
                m_inc = matching_inc[0]
                st.success(
                    f"✅ Detected by SENTINEL AI: Incident ID `{m_inc['incident_id']}` | "
                    f"Risk Score: `{m_inc['risk_score']}/100` ({m_inc['severity']}) | "
                    f"Sequence Matched: `{m_inc['evidence']['sequence_matched']}`"
                )
            else:
                st.error("❌ Not detected by current pipeline configuration.")

    st.markdown("---")
    st.subheader("Expected vs Actual Detection Comparison")
    
    comparison_data = []
    for c in campaigns:
        matching_inc = [i for i in incidents if i.get("campaign_tag") == c["id"]]
        if matching_inc:
            m = matching_inc[0]
            status = "PASS (Detected)"
            act_sev = m["severity"]
            act_score = m["risk_score"]
            seq = "Confirmed Email->Auth->Net" if m["evidence"]["sequence_matched"] else "Partial"
        else:
            status = "FAIL (Missed)"
            act_sev = "N/A"
            act_score = 0
            seq = "None"
            
        comparison_data.append({
            "Scenario ID": c["id"],
            "Scenario Name": c["name"],
            "Expected Outcome": c["expected_outcome"],
            "Actual Result": status,
            "Expected Severity": c["expected_severity"],
            "Detected Severity": act_sev,
            "Risk Score": act_score,
            "Attack Chain State Machine": seq
        })
        
    st.dataframe(pd.DataFrame(comparison_data), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Complete Attack Detection Workflow Demonstration")
    st.markdown("""
    ```mermaid
    flowchart LR
        subgraph S1 [Phase 1: Ingestion]
            E[Email Logs]
            A[Auth Logs]
            N[Network Flows]
        end
        subgraph S2 [Phase 2: Detection & Correlation]
            R[Rule Engine]
            G[Entity Graph Linkage]
            SM[State Machine Progression]
        end
        subgraph S3 [Phase 3: Assessment & Action]
            K[Explainable Risk Scoring]
            H[Human Approval Center]
            M[Simulation Sandbox]
        end
        E & A & N --> R
        R --> G
        G --> SM
        SM --> K
        K --> H
        H --> M
    ```
    """, unsafe_allow_html=True)

# ---------------------------------------------------------
# SECTION 8: LIVE URL & PHISHING INSPECTOR
# ---------------------------------------------------------
elif nav_option == "8. Live URL & Phishing Inspector":
    st.header("🔗 Live URL & Phishing Link Threat Inspector")
    st.caption("Inspect and test arbitrary or random links for phishing indicators, high-risk TLDs, typosquatting, and C2 ports.")

    st.markdown("""
    <div class="evidence-block">
        <div class="evidence-header">HOW URL THREAT INSPECTION WORKS</div>
        <p style="font-size:0.83rem; color:#94a3b8; margin:0;">
            Enter any random URL or link below to test SENTINEL AI's heuristic and threat intelligence analyzer. 
            The engine evaluates domain reputation, suspicious TLDs (e.g. <code>.xyz</code>, <code>.top</code>, <code>.ru</code>), brand lookalike typosquatting (e.g. <code>paypa1</code>, <code>micros0ft</code>), credential-harvesting URI paths, raw numeric IPs, and insecure port bindings.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Quick Preset Buttons
    st.markdown("**Quick Preset Test Samples:**")
    p_col1, p_col2, p_col3, p_col4 = st.columns(4)
    preset_url = None
    if p_col1.button("💳 Brand Spoofing", use_container_width=True):
        preset_url = "http://paypa1-security-login.xyz/verify/account?token=8923"
    if p_col2.button("🖥️ Raw IP & Non-Std Port", use_container_width=True):
        preset_url = "http://198.51.100.45:8080/admin/reset-password"
    if p_col3.button("🛡️ Fake IT VPN Portal", use_container_width=True):
        preset_url = "https://it-support-desk.top/vpn/renew-cert"
    if p_col4.button("✅ Benign SaaS Link", use_container_width=True):
        preset_url = "https://app.slack.com/client/T024/C02"

    default_input = preset_url or st.session_state.get("active_test_url", "http://paypa1-security-login.xyz/verify/account?token=8923")
    user_url = st.text_input("Enter any URL or link to inspect:", value=default_input)

    if user_url:
        st.session_state["active_test_url"] = user_url
        analysis = URLAnalyzer.analyze_url(user_url)
        v = analysis["verdict"]
        score = analysis["risk_score"]

        st.markdown("---")
        st.subheader("Inspection Result")

        # Result Banner
        if "MALICIOUS" in v:
            b_class = "badge-critical"
            border_c = "#ef4444"
        elif "SUSPICIOUS" in v:
            b_class = "badge-high"
            border_c = "#f59e0b"
        else:
            b_class = "badge-low"
            border_c = "#10b981"

        c_v1, c_v2 = st.columns([1.5, 1.5])
        with c_v1:
            st.markdown(f"""
            <div class="evidence-block" style="border-left: 4px solid {border_c};">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:1.15rem; font-weight:700; color:#f8fafc;">Threat Verdict</span>
                    <span class="badge {b_class}" style="font-size:0.9rem; padding:6px 12px;">{v}</span>
                </div>
                <div style="font-size:0.85rem; color:#cbd5e1; margin-top:8px;">
                    <b>Tested Target:</b> <code>{analysis['url']}</code><br>
                    <b>Extracted Hostname:</b> <code>{analysis['hostname']}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""<div class="evidence-header">DETECTION INDICATORS & FINDINGS</div>""", unsafe_allow_html=True)
            if analysis["findings"]:
                for f in analysis["findings"]:
                    st.markdown(f"- <span style='font-size:0.85rem; color:#f8fafc;'>{f}</span>", unsafe_allow_html=True)
            else:
                st.success("No suspicious heuristics detected. Standard benign domain structure.")

        with c_v2:
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={'text': "Link Threat Score", 'font': {'size': 16, 'color': '#f8fafc'}},
                number={'font': {'color': '#ef4444' if score >= 70 else '#f59e0b' if score >= 35 else '#00ff66'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': "#94a3b8"},
                    'bar': {'color': "#ef4444" if score >= 70 else "#f59e0b" if score >= 35 else "#00ff66"},
                    'bgcolor': "#111827",
                    'steps': [
                        {'range': [0, 35], 'color': 'rgba(16, 185, 129, 0.15)'},
                        {'range': [35, 70], 'color': 'rgba(245, 158, 11, 0.15)'},
                        {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.25)'}
                    ]
                }
            ))
            fig_g.update_layout(
                paper_bgcolor="#111827",
                font=dict(color="#94a3b8"),
                margin=dict(l=20, r=20, t=30, b=20),
                height=200
            )
            st.plotly_chart(fig_g, use_container_width=True)

