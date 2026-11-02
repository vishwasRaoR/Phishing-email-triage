import os, sys, time, base64, requests
from parse_email import parse_eml

VT_KEY = os.environ.get("VT_API_KEY")
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY")
SAFE_DOMAINS = ("googleapis.com", "gstatic.com", "google.com")

def is_private(ip):
    return ip.startswith(("10.", "192.168.", "127.")) or (
        ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)

def vt_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                     headers={"x-apikey": VT_KEY}, timeout=20)
    if r.status_code == 200:
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    return {"error": r.status_code}

def vt_ip(ip):
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers={"x-apikey": VT_KEY}, timeout=20)
    if r.status_code == 200:
        a = r.json()["data"]["attributes"]
        return {"stats": a["last_analysis_stats"],
                "country": a.get("country"), "owner": a.get("as_owner")}
    return {"error": r.status_code}

def vt_file(sha256):
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                     headers={"x-apikey": VT_KEY}, timeout=20)
    if r.status_code == 200:
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    return {"error": r.status_code}

def abuse_ip(ip):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
        if r.status_code == 200:
            d = r.json()["data"]
            return {"abuse_score": d["abuseConfidenceScore"],
                    "country": d["countryCode"], "isp": d["isp"]}
        return {"error": r.status_code}
    except requests.RequestException:
        return {"error": "AbuseIPDB unreachable"}

if __name__ == "__main__":
    data = parse_eml(sys.argv[1])
    print("== Sender IPs ==")
    for ip in dict.fromkeys(data["ips"]):
        if is_private(ip):
            continue
        print(ip, "VirusTotal:", vt_ip(ip))
        time.sleep(15)
        if ABUSE_KEY:
            print(ip, "AbuseIPDB:", abuse_ip(ip))
    print("== URLs ==")
    for url in data["urls"][:4]:
        if any(d in url for d in SAFE_DOMAINS):
            continue
        print(url, vt_url(url))
        time.sleep(15)
