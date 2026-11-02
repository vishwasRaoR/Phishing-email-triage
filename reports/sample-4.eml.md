# Phishing Triage Report: sample-4.eml

**Verdict:** HIGH risk (score 8)
**MITRE ATT&CK:** T1566 - Phishing

## Email details
- From: "[BB] - Seu saldo foi liberado - Código: 11084339647130851921" <prestonconstance587@gmail.com>
- Return-Path: prestonconstance587@gmail.com
- Subject: Liberação de IRPF - 6NwlyfzWcsNerv0
- Authentication: spf=pass (sender IP is 209.85.160.178) smtp.mailfrom=gmail.com; dkim=pass (signature was verified) header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass reason=100

## Findings
- Free-mail sender using brand/lure wording (possible impersonation)
- Attachment csWuYjyqO2IR.pdf (sha256 cfc5fbc759dcc599...)
- Attachment has a random-looking filename
- Attachment flagged malicious on VirusTotal: {'malicious': 18, 'suspicious': 0, 'undetected': 36, 'harmless': 0, 'timeout': 8, 'confirmed-timeout': 0, 'failure': 1, 'type-unsupported': 12}

## Indicators of compromise
- IP 209.85.160.178: {'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 37, 'harmless': 55, 'timeout': 0}, 'country': 'US', 'owner': 'Google LLC'}
- IP 20.97.213.223: {'stats': {'malicious': 0, 'suspicious': 0, 'undetected': 92, 'harmless': 0, 'timeout': 0}, 'country': 'US', 'owner': 'Microsoft Corporation'}

## Recommended actions
- Do not click links or open attachments
- Block the sender domain and IP at the mail gateway
- Delete the email from all mailboxes
- If anyone clicked a link: reset their password and review sign-in logs
- Escalate to L2 and record the IOCs above in the ticket
