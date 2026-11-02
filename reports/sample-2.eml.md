# Phishing Triage Report: sample-2.eml

**Verdict:** HIGH risk (score 10)
**MITRE ATT&CK:** T1566 - Phishing

## Email details
- From: "Microsoft account team", _ <no-reply@access-accsecurity.com>
- Return-Path: bounce@thcultarfdes.co.uk
- Subject: Microsoft account unusual signin activity
- Authentication: spf=none (sender IP is 89.144.44.2) smtp.mailfrom=thcultarfdes.co.uk; dkim=none (message not signed) header.d=none;dmarc=permerror action=none header.from=access-accsecurity.com;

## Findings
- SPF did not pass
- DKIM did not pass
- Reply-To domain differs from sender (gmail.com)
- Return-Path domain (thcultarfdes.co.uk) does not match From domain (access-accsecurity.com>)
- Link flagged on VirusTotal: http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176

## Indicators of compromise
- IP 89.144.44.2: {'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 37, 'harmless': 55, 'timeout': 0}, 'country': 'PL', 'owner': 'MSCode'}
- URL http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176: {'malicious': 9, 'suspicious': 1, 'undetected': 35, 'harmless': 48, 'timeout': 0}

## Recommended actions
- Do not click links or open attachments
- Block the sender domain and IP at the mail gateway
- Delete the email from all mailboxes
- If anyone clicked a link: reset their password and review sign-in logs
- Escalate to L2 and record the IOCs above in the ticket
