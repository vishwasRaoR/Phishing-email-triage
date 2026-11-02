# Phishing Triage Report: sample-3.eml

**Verdict:** HIGH risk (score 7)
**MITRE ATT&CK:** T1566 - Phishing

## Email details
- From: Zonnepanelen installateur <zonnepaneel@appjj.serenitepure.fr>
- Return-Path: return@dturm.de
- Subject: 🔋 Zonnepanelen voor een goede prijs 
- Authentication: spf=none (sender IP is 57.128.69.202) smtp.mailfrom=dturm.de; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=appjj.serenitepure.fr;compauth=fail reason=001

## Findings
- SPF did not pass
- DKIM did not pass
- Reply-To domain differs from sender (aichakandisha.com)
- Return-Path domain (dturm.de) does not match From domain (appjj.serenitepure.fr)

## Indicators of compromise
- IP 57.128.69.202: {'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 38, 'harmless': 54, 'timeout': 0}, 'country': 'FR', 'owner': 'OVH SAS'}
- URL http://go.nltrck.com/?c=495&amp;source=consumentenbond&amp;s1=&amp;lp=1190: {'malicious': 0, 'suspicious': 0, 'undetected': 35, 'harmless': 58, 'timeout': 0}
- URL https://i.imgur.com/Hr5TM3Y.png: {'malicious': 0, 'suspicious': 0, 'undetected': 32, 'harmless': 60, 'timeout': 0}
- URL https://i.imgur.com/sOPmaS3.png: {'malicious': 0, 'suspicious': 0, 'undetected': 32, 'harmless': 60, 'timeout': 0}

## Recommended actions
- Do not click links or open attachments
- Block the sender domain and IP at the mail gateway
- Delete the email from all mailboxes
- If anyone clicked a link: reset their password and review sign-in logs
- Escalate to L2 and record the IOCs above in the ticket
