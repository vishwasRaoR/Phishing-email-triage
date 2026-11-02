import os, re, sys, time, ipaddress
from email.utils import parseaddr
from parse_email import parse_eml
from enrich import vt_ip, vt_url, vt_file, is_private, SAFE_DOMAINS

FREE_MAIL = ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me")
LURE = ["banco", "bank", "saldo", "irpf", "paypal", "pix", "fatura",
        "refund", "reembolso", "invoice", "[bb]", "receita"]
URGENT = ["urgent", "verify", "suspended", "expir", "immediately", "act now",
          "urgente", "expirando", "hoje", "bloqueado", "confirme"]

def domain_of(addr):
    addr = parseaddr(addr or "")[1] or (addr or "")
    return addr.split("@")[-1].lower() if "@" in addr else ""

def triage(path):
    d = parse_eml(path)
    score, findings = 0, []

    auth = (d["auth_results"] or "").lower()
    if "spf=pass" not in auth:
        score += 2; findings.append("SPF did not pass")
    if "dkim=pass" not in auth:
        score += 1; findings.append("DKIM did not pass")

    from_dom = domain_of(d["from"])
    if d["reply_to"] and domain_of(d["reply_to"]) != from_dom:
        score += 2
        findings.append(f"Reply-To domain differs from sender ({domain_of(d['reply_to'])})")
    rp_dom = domain_of(d["return_path"])
    if rp_dom and from_dom and rp_dom != from_dom:
        score += 2
        findings.append(f"Return-Path domain ({rp_dom}) does not match From domain ({from_dom})")

    text = ((d["subject"] or "") + " " + d["body"]).lower()
    hits = [w for w in URGENT if w in text]
    if hits:
        score += 1
        findings.append("Urgency/pressure wording: " + ", ".join(hits))

    display = (parseaddr(d["from"] or "")[0] or "").lower()
    subj = (d["subject"] or "").lower()
    if from_dom in FREE_MAIL and any(w in display or w in subj for w in LURE):
        score += 3
        findings.append("Free-mail sender using brand/lure wording (possible impersonation)")

    ips = {}
    for ip in dict.fromkeys(d["ips"]):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if is_private(ip):
            continue
        res = vt_ip(ip); ips[ip] = res
        stats = res.get("stats", {})
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            score += 2
            findings.append(f"Sender IP {ip} flagged on VirusTotal: {stats}")
        time.sleep(15)

    urls = {}
    for url in d["urls"][:3]:
        if any(s in url for s in SAFE_DOMAINS):
            continue
        res = vt_url(url); urls[url] = res
        if res.get("malicious", 0) or res.get("suspicious", 0):
            score += 3
            findings.append(f"Link flagged on VirusTotal: {url}")
        host = re.sub(r"^https?://", "", url).split("/")[0]
        if len(host) > 20 and re.search(r"\d", host):
            score += 1
            findings.append(f"Link domain looks auto-generated: {host}")
        time.sleep(15)

    for att in d["attachments"]:
        score += 1
        findings.append(f"Attachment {att['name']} (sha256 {att['sha256'][:16]}...)")
        if re.fullmatch(r"[A-Za-z0-9]{10,}\.\w+", att["name"] or ""):
            score += 1
            findings.append("Attachment has a random-looking filename")
        res = vt_file(att["sha256"])
        if res.get("malicious", 0) > 0:
            score += 3
            findings.append(f"Attachment flagged malicious on VirusTotal: {res}")
        time.sleep(15)

    level = "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"
    return d, score, level, findings, ips, urls

def write_report(path, d, score, level, findings, ips, urls):
    os.makedirs("reports", exist_ok=True)
    out = os.path.join("reports", os.path.basename(path) + ".md")
    lines = [
        f"# Phishing Triage Report: {os.path.basename(path)}", "",
        f"**Verdict:** {level} risk (score {score})",
        "**MITRE ATT&CK:** T1566 - Phishing", "",
        "## Email details",
        f"- From: {d['from']}", f"- Return-Path: {d['return_path']}",
        f"- Subject: {d['subject']}",
        f"- Authentication: {d['auth_results']}", "",
        "## Findings",
    ]
    lines += [f"- {f}" for f in findings] or ["- No warning signs found"]
    lines += ["", "## Indicators of compromise"]
    lines += [f"- IP {ip}: {r}" for ip, r in ips.items()]
    lines += [f"- URL {u}: {r}" for u, r in urls.items()]
    lines += ["", "## Recommended actions"]
    if level == "LOW":
        lines += ["- Likely safe; no action needed"]
    else:
        lines += ["- Do not click links or open attachments",
                  "- Block the sender domain and IP at the mail gateway",
                  "- Delete the email from all mailboxes",
                  "- If anyone clicked a link: reset their password and review sign-in logs"]
    if level == "HIGH":
        lines += ["- Escalate to L2 and record the IOCs above in the ticket"]
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    return out

if __name__ == "__main__":
    path = sys.argv[1]
    result = triage(path)
    out = write_report(path, *result)
    print(f"{path}: score {result[1]} -> {result[2]} risk")
    for f in result[3]:
        print(" -", f)
    print("Report saved to", out)
