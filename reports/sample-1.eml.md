# Phishing Triage Report: sample-1.eml

**Verdict:** HIGH risk (score 9)
**MITRE ATT&CK:** T1566 - Phishing

## Email details
- From: BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>
- Return-Path: root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
- Subject: CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!
- Authentication: spf=temperror (sender IP is 137.184.34.4) smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06; dkim=none (message not signed) header.d=none;dmarc=temperror action=none header.from=atendimento.com.br;compauth=fail reason=001

## Findings
- SPF did not pass
- DKIM did not pass
- Return-Path domain (ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06) does not match From domain (atendimento.com.br)
- Urgency/pressure wording: expir, expirando, hoje
- Sender IP 137.184.34.4 flagged on VirusTotal: {'malicious': 0, 'suspicious': 1, 'undetected': 36, 'harmless': 55, 'timeout': 0}
- Link domain looks auto-generated: blog1seguimentmydomaine2bra.me

## Indicators of compromise
- IP 137.184.34.4: {'stats': {'malicious': 0, 'suspicious': 1, 'undetected': 36, 'harmless': 55, 'timeout': 0}, 'country': 'US', 'owner': 'DigitalOcean, LLC'}
- URL https://blog1seguimentmydomaine2bra.me/: {'malicious': 0, 'suspicious': 0, 'undetected': 37, 'harmless': 56, 'timeout': 0}

## Recommended actions
- Do not click links or open attachments
- Block the sender domain and IP at the mail gateway
- Delete the email from all mailboxes
- If anyone clicked a link: reset their password and review sign-in logs
- Escalate to L2 and record the IOCs above in the ticket
