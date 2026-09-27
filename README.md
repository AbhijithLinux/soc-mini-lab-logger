# SOC Mini-Lab Logger
Beginner-friendly SOC triage lab. No Wazuh install needed.

`python src/main.py` reads `data/sample_alert.json`, checks IP (offline demo), scores LOW/MEDIUM/HIGH, saves to SQLite, builds `output/report.html`.
