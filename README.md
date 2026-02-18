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

Scan specific target:

`python3 sroq.py -t 172.16.1.0/24`

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
    
- matplotlib
    
- openpyxl
    
- jq (optional, for validation)
