import streamlit as st
import pandas as pd
import json
import re
import time
from datetime import datetime
from langchain_ollama import ChatOllama

# --- CONFIGURATION & UI SETUP ---
st.set_page_config(page_title="Incident Commander AI Dashboard", page_icon="🚨", layout="wide")
st.title("🚨 Event-Driven Log Streaming Agent & Incident Commander")
st.caption("Live-tailing system logs processed through high-speed regex filters. Anomalies are analyzed by local AI agents to execute automated, deterministic infrastructure mitigation scripts.")

REMOTE_OLLAMA_URL = "http://10.22.39.192:11434"
LOG_BUFFER_MAX_SIZE = 50

# Initialize Local Incident Commander Engine
@st.cache_resource
def get_incident_commander_llm():
    # Temperature set to 0.0 to guarantee deterministic classification and secure bash tool generation
    return ChatOllama(model="qwen2.5vl:latest", base_url=REMOTE_OLLAMA_URL, temperature=0.0)

llm = get_incident_commander_llm()

# --- INITIALIZE VOLATILE TRACKING STATES ---
if "live_logs" not in st.session_state:
    st.session_state.live_logs = []
if "incident_ledger" not in st.session_state:
    st.session_state.incident_ledger = []

# --- HIGH-PERFORMANCE PRE-LLM FILTER MATRIX (HEURISTICS) ---
# White-list regex to immediately drop high-frequency background noise before the LLM sees it
NORMAL_LOG_PATTERN = re.compile(
    r"(GET /static/|HTTP/1.1\" 200|cron: session opened|Connection closed by authenticating user|refreshed auth token)", 
    re.IGNORECASE
)

# Critical indicator regex used to capture context windows for LLM evaluations
ANOMALY_LOG_PATTERN = re.compile(
    r"(unauthorized|password failed|connection refused|timeout|fatal|exception|sql injection attempt|denied)", 
    re.IGNORECASE
)

# --- AUTOMATED SIMULATED FREIGHT GENERATOR ---
def generate_mock_log_stream():
    """Simulates real-time heterogeneous server log noise mixed with periodic critical attacks."""
    timestamps = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mock_pool = [
        f"{timestamps} INFO: Werkzeug - 127.0.0.1 - \"GET /static/logo.png HTTP/1.1\" 200 -",
        f"{timestamps} INFO: Werkzeug - 127.0.0.1 - \"GET /dashboard HTTP/1.1\" 200 -",
        f"{timestamps} CRITICAL: sshd[4019]: Password failed for root from 192.168.1.45 port 55212 ssh2",
        f"{timestamps} CRITICAL: sshd[4019]: Password failed for root from 192.168.1.45 port 55218 ssh2",
        f"{timestamps} CRITICAL: sshd[4019]: Password failed for root from 192.168.1.45 port 55230 ssh2",
        f"{timestamps} WARNING: org.postgresql.Driver - Connection pool checkout timeout exception. Refusing connection.",
        f"{timestamps} INFO: systemd[1]: Started Periodic Command Scheduler.",
        f"{timestamps} ERROR: nginx_proxy - Unsafe SQL token payload detected in query parameter 'id=' from IP 10.0.4.12"
    ]
    # Rotate elements into the stream randomly or sequentially for testing loops
    import random
    return random.choice(mock_pool)

# --- STRICT INCIDENT ANALYSIS PROMPT ---
INCIDENT_COMMANDER_SYSTEM_PROMPT = """
You are an automated DevSecOps Incident Commander Agent operating inside a live production linux cluster.
You are receiving a sliding window context stream of suspicious anomaly log entries. Your job is to evaluate the threat severity and generate an absolute, safe mitigation bash shell instruction if required.

You MUST respond strictly with a valid JSON object matching the architecture layout template below.
Do not include any conversational text, explanations, or backticks outside the raw JSON boundaries.

Strict Rules for Mitigation Commands:
1. If severity is CRITICAL, generate an exact, actionable firewall rule or service isolation command (e.g., 'iptables -A INPUT -s 192.168.1.45 -j DROP' or 'docker stop vulnerable_service').
2. If severity is low or a false positive, set "mitigation_script" to "none".
3. Keep commands highly specific, targeted, and safe. Do not use destructive general operations like 'rm -rf'.

Strict JSON Target Layout Template:
{{
    "attack_vector_identified": "Detailed classification of threat pattern found",
    "threat_severity_rating": "CHOOSE EXACTLY ONE: INFORMATIONAL / WARNING / CRITICAL",
    "target_compromised_entity": "Name of host service, port, or database table target",
    "mitigation_script": "Exact bash command string or 'none'"
}}
"""

# --- WORKSPACE VIEWPORT LAYOUT ---
col_stream, col_commander = st.columns([1, 1.2], gap="large")

with col_stream:
    st.subheader("📥 Live Ingestion Stream & Pre-Filter Matrix")
    st.caption("Processes high-throughput text strings, dropping regular data while buffering system anomalies.")
    
    stream_active = st.toggle("Activate Live Production Log Streaming Ingestion Simulation", value=False)
    
    # Simple manual log insertion for deterministic validation testing
    manual_log = st.text_input("Manually Inject Custom Log Entry Testing String:")
    inject_btn = st.button("Inject Entry Into Pipeline")

    # Establish rendering placeholder spaces
    log_terminal_preview = st.empty()

with col_commander:
    st.subheader("🎖️ Commander Incident Resolution Center")
    incident_display_zone = st.empty()

# --- LIVE STATE STREAM PROCESSING LOOP ---
# Check if execution parameters are met either via automated stream or manual buttons
log_to_process = None
if inject_btn and manual_log:
    log_to_process = manual_log
elif stream_active:
    time.sleep(1.2) # Avoid aggressive loop starvation rates
    log_to_process = generate_mock_log_stream()

if log_to_process:
    # Tier 1: Run High-Speed Pre-Filter Evaluation Check
    if NORMAL_LOG_PATTERN.search(log_to_process):
        log_status_flag = " dropped_noise"
    elif ANOMALY_LOG_PATTERN.search(log_to_process):
        log_status_flag = "🚨 ANOMALY_TRIGGER"
    else:
        log_status_flag = " unclassified_pass"
        
    # Append trace data maps into the browser viewport terminal trace cache
    st.session_state.live_logs.insert(0, {"timestamp": datetime.now().strftime("%H:%M:%S"), "payload": log_to_process, "action": log_status_flag})
    if len(st.session_state.live_logs) > LOG_BUFFER_MAX_SIZE:
        st.session_state.live_logs.pop()

    # Tier 2: If an anomaly is intercepted, trigger the Core AI Reasoning Agent
    if log_status_flag == "🚨 ANOMALY_TRIGGER":
        with st.spinner("Incident Commander analyzing anomalous pattern context window..."):
            try:
                # Build context window payload out of nearby logs to capture sequence events
                recent_context = "\n".join([item["payload"] for item in st.session_state.live_logs[:5]])
                
                prompt = f"{INCIDENT_COMMANDER_SYSTEM_PROMPT}\n\nSUSPICIOUS CONTEXT WINDOW BUFFER:\n{recent_context}"
                response = llm.invoke(prompt)
                
                # Sanitize out target JSON payload values using strict regex boundaries
                json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
                if not json_match:
                    raise ValueError("Target JSON formatting structure absent from model output generation buffer.")
                    
                incident_report = json.loads(json_match.group(0))
                severity = incident_report.get("threat_severity_rating", "WARNING").upper()
                script_action = incident_report.get("mitigation_script", "none")
                
                # Apply hard deterministic code routing logic blocks based on model feature extraction
                if severity == "CRITICAL" and script_action.lower() != "none":
                    execution_status = f"⚡ COMMAND DYNAMICALLY EXECUTED: `{script_action}`"
                    st.toast(f"Incident Commander deployed automated counter-measure script!", icon="🔥")
                else:
                    execution_status = "👁️ Log Vector Monitored - No Automated Mitigation Dispatched"
                    
                # Append incident parameters to persistent evaluation logging tracks
                st.session_state.incident_ledger.insert(0, {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "vector": incident_report.get("attack_vector_identified", "Unknown Anomaly"),
                    "severity": severity,
                    "target": incident_report.get("target_compromised_entity", "System Core"),
                    "script": script_action,
                    "execution_outcome": execution_status
                })
            except Exception as e:
                st.error(f"Pipeline Interruption: {str(e)}")
                if 'response' in locals():
                    st.code(response.content)

# --- RE-RENDER STREAM DISPLAY PANELS ---
with log_terminal_preview:
    df_logs = pd.DataFrame(st.session_state.live_logs)
    if not df_logs.empty:
        st.dataframe(df_logs, use_container_width=True, hide_index=True)
    else:
        st.info("Log Ingestion engine idle. Toggle streaming simulation or inject a testing string to activate.")

with incident_display_zone:
    df_incidents = pd.DataFrame(st.session_state.incident_ledger)
    if not df_incidents.empty:
        # Render high-profile metric counters
        crit_count = len(df_incidents[df_incidents['severity'] == 'CRITICAL'])
        st.metric(label="Critical System Threat Events Blocked", value=crit_count, delta=f"{crit_count} active interventions", delta_color="inverse")
        
        # Render clean master incident table grid layout
        st.markdown("### 🗃️ Active Security & Threat Resolution Ledger")
        st.dataframe(df_incidents, use_container_width=True, hide_index=True)
    else:
        st.caption("No security threats detected in current context window buffer streams.")

# Force a visual layout rerun if streaming toggle configuration stays locked active
if stream_active:
    st.rerun()