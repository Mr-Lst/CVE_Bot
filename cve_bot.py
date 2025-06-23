import requests
import json
import os
import time
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv("webhook-key.env")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
NVD_API_KEY = os.getenv("NVD_API_KEY")
SENT_CVES_FILE = "sent_cves.json"

def get_color(score, severity):
    severity = (severity or "").upper()
    if severity == "CRITICAL":
        return 0x23272A
    if severity == "HIGH":
        return 0xFF0000
    if severity == "MEDIUM":
        return 0xFFA500
    if severity == "LOW":
        return 0xFFFF00
    if severity == "NONE":
        return 0x808080
    if score >= 9.0:
        return 0xFF0000
    if score >= 7.0:
        return 0xFFA500
    if score >= 4.0:
        return 0xFFFF00
    if score > 0.0:
        return 0x00FFFF
    return 0x808080

def load_sent_cves():
    if os.path.exists(SENT_CVES_FILE):
        try:
            with open(SENT_CVES_FILE, "r") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_sent_cves(sent_cves):
    with open(SENT_CVES_FILE, "w") as f:
        json.dump(list(sent_cves), f)

def fetch_recent_cves():
    now = datetime.now(timezone.utc)
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    pub_start = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=20"
    )
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    print("Fetching CVEs from:", url)
    res = requests.get(url, headers=headers, timeout=30)
    if res.status_code != 200:
        print("NVD API Error:", res.status_code, res.text)
        return []
    data = res.json()
    return data.get("vulnerabilities", [])

def create_embed(cve_item):
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "Unknown")
    description = "No summary available."
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break
    published = cve.get("published", datetime.now(timezone.utc).isoformat())
    references = [r["url"] for r in cve.get("references", []) if "url" in r]

    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        unix_ts = int(dt.timestamp())
        published_discord = f"<t:{unix_ts}:f>"
    except Exception:
        published_discord = published

    score = 0.0
    severity = "Unknown"
    cvss_data = {}
    metrics = cve.get("metrics", {})
    for key in metrics:
        if key.startswith("cvssMetric") and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            break
    score = float(cvss_data.get("baseScore", 0.0)) if "baseScore" in cvss_data else 0.0
    severity = cvss_data.get("baseSeverity", "Unknown") if "baseSeverity" in cvss_data else "Unknown"

    cwe = "N/A"
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        descs = weaknesses[0].get("description", [])
        if descs:
            cwe = descs[0].get("value", "N/A")
    if cwe.startswith("CWE-"):
        cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"
    else:
        cwe_url = "https://cwe.mitre.org"

    products = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                product = match.get("criteria") or match.get("cpeName") or ""
                if match.get("vulnerable") and product:
                    products.append(product)
    products = list(dict.fromkeys(products))

    key_factors = [
        f"🔐 Auth Required: {cvss_data.get('privilegesRequired', 'Unknown')}",
        f"🎯 Exploitability: {cvss_data.get('attackComplexity', 'Unknown')}",
        f"👤 User Interaction: {cvss_data.get('userInteraction', 'Unknown')}",
        f"💥 Public Exploit: {'Yes' if 'exploit' in description.lower() else 'Unknown'}"
    ]

    embed = {
        "title": f"🚨 New CVE: {cve_id}",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "description": description,
        "color": get_color(score, severity),
        "fields": [
            {"name": "🧬 CWE ID", "value": f"[{cwe}]({cwe_url})"},
            {"name": "📊 CVSS Score", "value": f"{severity} ({score}/10.0)" if score > 0 else "Unknown"},
            {"name": "📦 Affected Products", "value": "\n".join(products[:5]) if products else "N/A"},
            {"name": "📌 Key Factors", "value": "\n".join(key_factors)},
            {"name": "📅 Published", "value": published_discord, "inline": True},
            {"name": "🔗 References", "value": "\n".join(references[:3]) if references else "No references found."}
        ],
        "footer": {"text": f"Fetched {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"}
    }
    return embed

def send_to_discord(embed):
    payload = {"embeds": [embed]}
    try:
        res = requests.post(DISCORD_WEBHOOK, json=payload, timeout=15)
        print("Discord response status:", res.status_code)
        print("Discord response text:", res.text)
        res.raise_for_status()
        return True
    except Exception as e:
        print("Discord Exception:", e)
        return False

def main():
    print("🚩 Bot started")
    sent_cves = load_sent_cves()
    cves = fetch_recent_cves()
    print("Discovered CVEs:", len(cves))
    new = 0
    for item in cves:
        cve_id = item.get("cve", {}).get("id")
        print("CVE found:", cve_id)
        if not cve_id or cve_id in sent_cves:
            continue
        embed = create_embed(item)
        if send_to_discord(embed):
            print(f"✅ Sent: {cve_id}")
            sent_cves.add(cve_id)
            new += 1
        else:
            print(f"❌ Failed to send: {cve_id}")
    print("📌 New CVEs sent:", new)
    save_sent_cves(sent_cves)

if __name__ == "__main__":
    while True:
        main()
        time.sleep(60)
