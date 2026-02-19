# Sroq

**Sroq** is a lightweight network vulnerability reporting tool built around Nmap + vulners.

It performs network scans, aggregates unique CVEs per host, calculates weighted risk scores, and generates structured reports in JSON, PNG, CSV, and Excel formats.

Designed to be simple, headless, and automation-friendly.

---

## Features

- Network scanning via `nmap -sV --script vulners`
    
- Unique CVE aggregation per host
    
- Severity breakdown:
    
    - critical / high / medium / low / unknown
        
- Deterministic CVE sorting (CVSS desc, ID asc)
    
- Weighted risk score per host
    
- CVSS sum metric per host
    
- Stacked severity graph (PNG)
    
- Flat reporting export:
    
    - JSON
        
    - CSV
        
    - Excel (.xlsx)
        

---

## Risk Scoring Model

Weighted severity formula:

`risk_score =   critical * 10 +   high     * 6  +   medium   * 3  +   low      * 1  +   unknown  * 2`

This intentionally biases toward high-impact vulnerabilities.

Additionally:

- `risk_cvss_sum` = sum of unique CVE CVSS values
    
- `max_cvss` per host
    
- Full unique CVE list stored in JSON
    

---

## CLI Usage

Basic scan:

`python3 sroq.py`

Generate graph:

`python3 sroq.py -g`

Generate CSV:

`python3 sroq.py -c`

Generate Excel (also generates CSV automatically):

`python3 sroq.py -x`

Send email report (requires SMTP_* env vars):

`python3 sroq.py -e`

Scan specific target:

`python3 sroq.py -t 172.16.1.0/24`

Verbose output:

`python3 sroq.py -v`

---

## Email Configuration

To send scan reports via email, set these environment variables before running:

**Required:**
- `SMTP_HOST` - SMTP server hostname (e.g., `smtp.gmail.com`)
- `SMTP_PORT` - SMTP port (typically 465 for SSL, 587 for TLS)
- `SMTP_USER` - SMTP username (usually your email address)
- `SMTP_PASS` - SMTP password or app-specific password
- `SROQ_EMAIL_TO` - Recipient email address

**Optional:**
- `SROQ_EMAIL_FROM` - Sender email address (defaults to SMTP_USER if not set)

Example:

```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="465"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASS="your-app-password"
export SROQ_EMAIL_TO="recipient@example.com"

python3 sroq.py -e
```

Email report includes:
- Network summary (total hosts, total CVEs)
- Top 5 riskiest hosts globally
- Attachments (CSV, XLSX, PNG, JSON if generated)

---

## Security Notes

**⚠️ Do NOT commit credentials or secrets to version control:**

- Never commit `sroq.yml` if it contains actual scan targets/credentials
- Never commit shell scripts with hardcoded SMTP passwords
- Use environment variables or `.env` files (add to `.gitignore`) for sensitive data
- Consider using a secrets manager for automated deployments

---

## Output Files

All outputs share the same base filename:

`sroq_<timestamp>.json sroq_<timestamp>.png sroq_<timestamp>.csv sroq_<timestamp>.xlsx`

---

## Output Structure

Each host contains:

- Open ports
    
- Unique CVE count
    
- Full CVE list (id + cvss)
    
- Severity distribution
    
- max_cvss
    
- risk_score
    
- risk_cvss_sum
    

Graph output:

- Hosts sorted by descending risk_score
    
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
