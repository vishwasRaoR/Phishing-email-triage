import email, re, hashlib, sys
from email import policy

def parse_eml(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    data = {
        "file": path,
        "from": msg["From"],
        "reply_to": msg["Reply-To"],
        "return_path": msg["Return-Path"],
        "subject": msg["Subject"],
        "auth_results": msg["Authentication-Results"],
    }

    # IP addresses found in the Received headers (mail server hops)
    ips = []
    for r in msg.get_all("Received", []):
        ips += re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", r)
    data["ips"] = ips

    # Body text and every URL in it
    body = ""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part:
        body = part.get_content()
    data["urls"] = sorted(set(re.findall(r"https?://[^\s\"'<>]+", body)))
    data["body"] = body

    # Attachments and their SHA256 hashes
    atts = []
    for att in msg.iter_attachments():
        payload = att.get_payload(decode=True) or b""
        atts.append({"name": att.get_filename(),
                     "sha256": hashlib.sha256(payload).hexdigest()})
    data["attachments"] = atts
    return data

if __name__ == "__main__":
    result = parse_eml(sys.argv[1])
    for key, value in result.items():
        if key != "body":
            print(f"{key}: {value}")
