# Day 19 — Web Access Log Attack Detector (SOC analysis)

A beginner-friendly SOC triage tool: reads web server access log lines
(Apache/Nginx combined format) and flags SQL injection probes, path
traversal, XSS attempts, command-execution probes, sensitive-file
scanning, and known scanner user-agents — plus a behavioral
"404/5xx spray" rule. Outputs a SOC-style incident summary with
severity-ranked alerts and next steps.

- `attack_detector.py` — the detector (stdlib only, fully offline)
- `sample_access.log` — sample log (RFC 5737 doc-range IPs only)
- `guide-day19.md` — plain-English guide

Run: `python3 attack_detector.py` (built-in sample) or
`python3 attack_detector.py sample_access.log`
