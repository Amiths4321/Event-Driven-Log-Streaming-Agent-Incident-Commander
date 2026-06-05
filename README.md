# 🚨 Event-Driven Log Streaming Agent & Incident Commander

An automated, event-driven security and operations logging dashboard that intercepts high-throughput log streams, applies pre-LLM regex filtering heuristics to drop routine noise, compiles rolling contextual anomalies, and uses a local reasoning engine to execute automated system countermeasures.

Powered by **LangChain v0.3**, **Streamlit**, **Pandas**, and a local **Qwen2.5-Coder** engine running on dedicated hardware, this application establishes a secure, network-isolated incident command workspace.

---

## 🚀 Key Architectural Features

* **Two-Tier High-Speed Filter Architecture**: Combines low-latency python regular expressions with local AI models to discard predictable background noise before inference runs.
* **Sliding Context Window Buffering**: Tracks sequential event lines over a rolling history matrix, giving the reasoning agent the full context needed to catch multi-stage attacks.
* **Deterministic Action Containment**: Implements hard-coded conditional routing rules that enforce absolute code-execution boundaries, triggering scripts only during verified `CRITICAL` conditions.
* **Structured Command Payload Serialization**: Uses explicit system instructions to constrain model outputs to strict JSON formats, extracting targeted mitigation parameters like firewall rules or container terminations.
* **Live Analytics & Threat Incident Management**: Maps active incident lists to Pandas dataframes to provide real-time updates on blocked threats and system intervention states.

---

## 🛠️ Environment Isolation & Workspace Deployment

To protect your system path environment from version collisions with core updates, deploy this application inside an isolated Python virtual environment sandbox:

```bash
# Navigate to the workspace project path root folder
cd log_incident_commander

# Establish and activate local Python environment isolation
python -m venv venv
source venv/bin/activate      # On Windows Use: venv\Scripts\activate

# Install exact cross-compatible package footprints
pip install streamlit pandas
pip install "langchain-core>=0.3.68,<1.0.0"
pip install "langchain-ollama>=0.2.0,<1.0.0"
