# email-audit

A command-line tool that audits **DMARC**, **SPF**, and **MX** configuration for a list of domains, and exports results to Excel (`.xlsx`) and optionally Word (`.docx`).

## Features

- **DMARC**: detects missing records, weak policies (`none`), multiple records, and missing `p=` tags
- **SPF**: detects missing records, multiple records, and extracts explicit `ip4:`/`ip6:` addresses
- **MX ASN**: resolves mail-gateway hostnames → IPs → reverse DNS + ASN (via RDAP)
- **Mail-A ASN**: probes common subdomains (`mail.*`, `smtp.*`, etc.) to surface real mail servers behind security gateways
- **Word output**: per-domain tables with side-by-side DMARC/SPF config and MX info

## Requirements

```bash
pip install dnspython openpyxl ipwhois python-docx
```

> `ipwhois` is optional — ASN columns will show `N/A` without it.  
> `python-docx` is only required when using `--output-docx`.

## Usage

```bash
# Basic — reads domains.txt, writes dmarc_results.xlsx
python email-audit.py domains.txt

# Custom output path
python email-audit.py domains.txt --output results.xlsx

# Also generate a Word document
python email-audit.py domains.txt --output results.xlsx --output-docx results.docx

# CSV input with a specific domain column
python email-audit.py domains.csv --column domain

# Use a custom DNS resolver
python email-audit.py domains.txt --nameserver 8.8.8.8
```

## Input Format

| Format | Description                                                         |
| ------ | ------------------------------------------------------------------- |
| `.txt` | One domain per line                                                 |
| `.csv` | Auto-detects `domain`/`hostname` column, or specify with `--column` |

## Output Columns (Excel)

| Column           | Description                                          |
| ---------------- | ---------------------------------------------------- |
| Domain           | The queried domain                                   |
| DMARC Found      | `True`/`False` - red if missing                      |
| DMARC Record     | Raw TXT record                                       |
| DMARC Policy     | `none` / `quarantine` / `reject` - red if `none`     |
| DMARC Sub-Policy | Subdomain policy (`sp=`)                             |
| DMARC Pct        | Percentage of mail covered (`pct=`, default 100)     |
| DMARC RUA/RUF    | Reporting URIs                                       |
| SPF Found        | `True`/`False`                                       |
| SPF Record       | Raw TXT record                                       |
| SPF IPs          | Explicit `ip4:`/`ip6:` addresses                     |
| SPF Qualifier    | `+all`, `-all`, `~all`, or `?all`                    |
| MX ASN           | ASN of the MX mail gateway                           |
| Mail A ASN       | ASN of the real mail server (from subdomain probing) |
