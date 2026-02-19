# Sroq

**Sroq** is a lightweight, headless network vulnerability reporting tool built around **Nmap + vulners**.

It performs network scans, aggregates unique CVEs per host, calculates weighted risk scores, generates structured reports in JSON, PNG, CSV, and Excel formats, and can send an email report with the outputs attached.

Sroq is designed to be simple, deterministic, and automation-friendly.

---

## Features

- Network scanning via `nmap -sV --script vulners`    
- Unique CVE aggregation per host
- Severity breakdown:
    - critical / high / medium / low / unknown
- Deterministic CVE sorting (CVSS desc, ID asc)
- Weighted risk score per host
- CVSS sum metric (`risk_cvss_sum`)
- Stacked severity visualization (PNG)
- Structured reporting export:
    - JSON
    - CSV
    - Excel (.xlsx)
- Optional automated email reporting with attachments
    

---

## Risk Scoring Model

Weighted severity formula:

`risk_score = critical * 10 + high * 6 + medium * 3 + low * 1 + unknown * 2`

This intentionally biases toward high-impact vulnerabilities.

Additionally:

- `risk_cvss_sum` = sum of unique CVE CVSS values
- `max_cvss` per host
- Full unique CVE list stored in JSON
- Hosts sorted by descending `risk_score` in graph and email output

---

## CLI Usage

Basic scan:

`python3 sroq.py`

Generate graph:

`python3 sroq.py -g`

Generate CSV:

`python3 sroq.py -c`

Generate Excel (automatically generates CSV as well):

`python3 sroq.py -x`

Send email report:

`python3 sroq.py -e`

Scan specific target:

`python3 sroq.py -t 172.16.1.0/24`

Verbose output:

`python3 sroq.py -v`

---

## Configuration (`sroq.yml`)

Sroq behavior can be controlled via `sroq.yml`.

### Report Defaults

These control default behavior when CLI flags are not specified.

`report:   graph_default: false   csv_default: false   excel_default: false   email_default: false`

CLI flags always override these defaults.

---

## Email Configuration

Sroq supports two configuration methods for SMTP settings:

1. `email:` block in `sroq.yml` (recommended for lab use)
    
2. Environment variables (`SMTP_*`, `SROQ_*`)
    

### Configuration Precedence

1. Values defined under `email:` in `sroq.yml`
    
2. Environment variables (used only if a key is missing in YAML)
    

This allows fully self-contained lab configuration while still supporting secure overrides in CI or production environments.

---

### Example `sroq.yml`

`email:   smtp_host: "smtp.gmail.com"   smtp_port: 465   smtp_user: "YOUR_EMAIL@gmail.com"   smtp_pass: "YOUR_APP_PASSWORD"   to: "RECIPIENT_EMAIL@gmail.com"   # from: "optional_sender@gmail.com"  # defaults to smtp_user if omitted`

---

### Environment Variable Alternative

`export SMTP_HOST="smtp.gmail.com" export SMTP_PORT="465" export SMTP_USER="your-email@gmail.com" export SMTP_PASS="your-app-password" export SROQ_EMAIL_TO="recipient@example.com"  python3 sroq.py -e`

---

### Email Report Includes

- Network summary (total networks, hosts, CVEs    
- Top 5 riskiest hosts globally
- Attachments (CSV, XLSX, PNG, JSON if generated)

---

## Output Files

All outputs share the same base filename:

`sroq_<timestamp>.json sroq_<timestamp>.png sroq_<timestamp>.csv sroq_<timestamp>.xlsx`

---

## Output Structure

Each host entry contains:

- Open ports    
- Unique CVE count
- Full CVE list (id + cvss)
- Severity distribution
- `max_cvss`
- `risk_score`
- `risk_cvss_sum`
### Graph Output

- Hosts sorted by descending `risk_score    
- Stacked severity bars
- Annotated with CVE count and risk score

---

## Requirements

- Python 3.9+    
- nmap
- python-nmap
- PyYAML
- matplotlib
- openpyxl
- jq (optional, for validation)

## Author, License

Written by Saar Yachin, https://www.saaryachin.com, with the assistance of Chat and Claude. Check out my other cybersecurity and homelab repos! 
