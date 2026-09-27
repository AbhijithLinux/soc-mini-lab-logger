import json, sqlite3, pathlib, datetime, os, urllib.request, urllib.parse
BASE = pathlib.Path(__file__).resolve().parent.parent
DB = BASE/"output"/"alerts.db"

def load_env():
    p = BASE/".env"
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k,v = line.split("=",1); os.environ.setdefault(k.strip(), v.strip())
load_env()
def load_alert(p):
    return json.loads(pathlib.Path(p).read_text())

def check_ip_offline(ip):
    try: return "clean" if int(ip.split(".")[-1])%2==0 else "suspicious"
    except: return "invalid"

def check_ip_abuseipdb(ip, key):
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        score = json.load(r)["data"]["abuseConfidenceScore"]
    if score >= 75: return f"malicious({score})"
    if score >= 25: return f"suspicious({score})"
    return f"clean({score})"

def check_ip(ip):
    key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if key:
        try: return check_ip_abuseipdb(ip, key)
        except Exception as e: print(f"AbuseIPDB fail ({e}), using offline"); return check_ip_offline(ip)
    return check_ip_offline(ip)

def risk(sev, intel):
    if sev=="critical" or intel=="malicious": return "HIGH"
    if intel=="suspicious" or sev=="medium": return "MEDIUM"
    return "LOW"

def save(a, intel, final):
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS alerts(ts,alert_id,indicator,intel,risk)")
    c.execute("INSERT INTO alerts VALUES(?,?,?,?,?)",(datetime.datetime.now().isoformat(),a["alert_id"],a["indicator"],intel,final))
    c.commit(); c.close()

def report():
    c = sqlite3.connect(DB)
    rows = c.execute("SELECT * FROM alerts").fetchall(); c.close()
    html = "<h1>SOC Mini-Lab Report</h1><table border=1><tr><th>Time</th><th>ID</th><th>IOC</th><th>Intel</th><th>Risk</th></tr>"
    for r in rows: html+=f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>"
    (BASE/"output"/"report.html").write_text(html+"</table>")
    print(f"Saved {len(rows)} alerts -> output/report.html")

if __name__=="__main__":
    a = load_alert(BASE/"data"/"sample_alert.json")
    intel = check_ip(a["indicator"])
    final = risk(a.get("severity","low"), intel)
    save(a, intel, final)
    print(f'{a["alert_id"]} {a["indicator"]} -> {intel} -> {final}')
    report()
