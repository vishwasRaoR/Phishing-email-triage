# Phishing Email Triage Tool

A Python tool that automates the first-level (L1 SOC) triage of suspicious emails. It parses a `.eml` file, enriches the indicators with VirusTotal, scores the risk, and writes an analyst-style incident report.

## What it does
1. **Parses** the email: sender, Reply-To, Return-Path, SPF/DKIM results, Received-header IPs, links and attachments (SHA256).
2. **Enriches** indicators with the VirusTotal API: sender IPs, URLs and attachment hashes.
3. **Scores** the email using weighted rules and labels it LOW, MEDIUM or HIGH risk.
4. **Reports**: saves a Markdown report with findings, IOCs, MITRE ATT&CK mapping (T1566 Phishing) and recommended actions.

## Scoring rules
| Signal | Points |
|---|---|
| SPF fails | +2 |
| DKIM fails | +1 |
| Reply-To domain differs from sender | +2 |
| Return-Path domain differs from From domain | +2 |
| Urgency/pressure wording (EN/PT) | +1 |
| Free-mail sender with brand/lure wording | +3 |
| Sender IP flagged on VirusTotal | +2 |
| Link flagged on VirusTotal | +3 |
| Auto-generated looking link domain | +1 |
| Attachment present / random filename | +1 / +1 |
| Attachment flagged malicious on VirusTotal | +3 |

Verdict: 0-2 LOW, 3-5 MEDIUM, 6+ HIGH.

## Results on public phishing samples
| Sample | Score | Verdict | Key findings |
|---|---|---|---|
| sample-1 | 9 | HIGH | Bank impersonation, SPF/DKIM fail, cloud-server Return-Path, auto-generated link domain |
| sample-2 | 10 | HIGH | Reply-To mismatch, link flagged on VirusTotal |
| sample-3 | 7 | HIGH | Reply-To and Return-Path mismatch |
| sample-4 | 8 | HIGH | Free-mail impersonation, malicious PDF (18 engines) |

**Lesson learned:** my first version rated sample-4 LOW (score 1). The attacker used a real Gmail account, so SPF and DKIM passed. I added attachment hash lookups and a free-mail impersonation rule, and it is now HIGH. Passing authentication does not mean an email is safe.

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install requests
export VT_API_KEY="your_virustotal_key"   # free key from virustotal.com
python3 triage.py path/to/email.eml
```
The API key is read from an environment variable and is never stored in the code.

## Limitations
- A clean VirusTotal result does not prove an email is safe. New phishing domains are often not flagged yet.
- Rules are simple heuristics and can give false positives and false negatives.
- The free VirusTotal tier is limited to 4 requests per minute, so each email takes about a minute.
- Words lists cover English and Portuguese only.

## Future work
- Add AbuseIPDB as a second IP reputation source.
- Train an ML model on labelled phishing data to replace or support the rules.
- Send results into Splunk as a dashboard.
- Sandbox analysis of attachments.

Only use this tool on emails you are authorised to analyse, and never open links or attachments from phishing samples.
