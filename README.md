# SOC Mini-Lab Logger — My Notes

> Beginner-friendly SOC triage lab. No Wazuh install. 1 command run.
> I built this to learn how SOC analysts triage alerts: ingest → intel → risk → store → report.

## What I learned
- SOC gets 100s of alerts daily (alert fatigue). Manual check = copy IP → VirusTotal/AbuseIPDB → decide → notify → document. Slow.
- Automation does same in 5 sec with proof (SQLite + HTML report).

## How it works (my words)
1. **Alert in:** `data/sample_alert.json` is fake Wazuh alert. Has `alert_id, indicator (IP), severity`.
2. **Read:** `load_alert()` loads JSON to dict.
3. **Intel check:**
   - No key → offline demo: last octet even = clean, odd = suspicious.
   - With `ABUSEIPDB_KEY` → live call `GET api.abuseipdb.com/api/v2/check`, reads `abuseConfidenceScore`: >=75 malicious, >=25 suspicious, else clean.
   - Fail (no net/bad key) → falls back to offline, never crashes.
4. **Risk:** `critical/malicious = HIGH`, `medium/suspicious = MEDIUM`, else `LOW`.
5. **Store:** SQLite `output/alerts.db` table `alerts(ts,alert_id,indicator,intel,risk)`.
6. **Report:** `output/report.html` table view.

## Run
```
# offline (no key needed)
python src/main.py

# live (free key)
copy .env.example .env
# edit .env -> ABUSEIPDB_KEY=your_key
python src/main.py
```

## Test I did
| ID | IP | Intel | Risk | Why |
|----|----|-------|------|-----|
| LAB-001 | 8.8.8.8 | clean | MEDIUM | severity medium overrides |
| LAB-002 | 1.1.1.1 | suspicious | MEDIUM | suspicious |
| LAB-003 | 8.8.8.8 | clean | LOW | low + clean |
| LAB-003 live | 8.8.8.8 | clean(0) | LOW | real score 0 |

Delete `output/alerts.db` to reset history.

## Files
- `src/main.py` — all logic (~60 lines, stdlib only)
- `data/sample_alert.json` — change IP/severity to test
- `output/` — db + html (db ignored by git)
- `.env.example` — copy to `.env`, never commit real key

## Next (v3 ideas)
- Domain/URL support via VirusTotal
- Slack webhook notify on HIGH
- Watch folder for many alerts

---
*Note by AbhijithLinux — learning SOC by building.*
