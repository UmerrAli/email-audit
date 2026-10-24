#!/usr/bin/env python3
"""
dmarc_check.py

Reads a CSV or TXT file containing a list of domains. For each domain, queries
DNS records and checks:
  - DMARC  (_dmarc.<domain> TXT)  — policy, pct, rua/ruf, issue
  - SPF    (<domain> TXT)          — record, extracted IPs, qualifier
  - MX ASN — ASN of the mail gateway (from MX records)
  - Mail A ASN — ASN of the real mail server (from mail.*/smtp.* A records)

Output defaults to Excel (.xlsx). Use --output-docx to also produce a Word doc.

Usage:
    python email-audit.py domains.txt
    python email-audit.py domains.txt --output results.xlsx
    python email-audit.py domains.txt --output results.xlsx --output-docx results.docx
    python email-audit.py domains.csv --column domain

Requirements:
    pip install dnspython python-docx openpyxl ipwhois
"""

import argparse
import csv
import re
import socket
import sys

# ── Third-party dependencies ──────────────────────────────────────────────────

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:
    sys.exit("Missing dependency 'dnspython'.  Install:  pip install dnspython")

try:
    import docx
except ImportError:
    docx = None  

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
except ImportError:
    sys.exit("Missing dependency 'openpyxl'.  Install:  pip install openpyxl")

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print("[WARN] 'ipwhois' not installed — ASN info will be N/A.  "
          "Install:  pip install ipwhois", file=sys.stderr)


# Record types queried per domain
DEFAULT_RECORD_TYPES = ["MX", "TXT", "A"]

# Subdomain prefixes probed via A/AAAA to find the real mail server
MAIL_SUBDOMAIN_PREFIXES = ["mail", "smtp", "mx", "mx1", "mx2", "mailhost", "webmail", "email"]

# DMARC helpers 

def parse_dmarc_tags(record: str) -> dict:
    """Split a DMARC TXT string (semicolon-separated) into a {tag: value} dict."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str, resolver: "dns.resolver.Resolver") -> dict:
    """
    Query _dmarc.<domain> for a TXT record and parse its tags.
    Returns a dict with keys: dmarc_found, dmarc_record, dmarc_policy,
    dmarc_subdomain_policy, dmarc_pct, dmarc_rua, dmarc_ruf, dmarc_issue.
    """
    result = {
        "dmarc_found": False,
        "dmarc_record": "",
        "dmarc_policy": "",
        "dmarc_subdomain_policy": "",
        "dmarc_pct": "",
        "dmarc_rua": "",
        "dmarc_ruf": "",
        "dmarc_issue": "",
    }

    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except dns.resolver.NXDOMAIN:
        result["dmarc_issue"] = "No _dmarc record (NXDOMAIN)"
        return result
    except dns.resolver.NoAnswer:
        result["dmarc_issue"] = "No TXT record at _dmarc subdomain"
        return result
    except dns.exception.Timeout:
        result["dmarc_issue"] = "DNS query timed out"
        return result
    except Exception as e:
        result["dmarc_issue"] = f"DNS lookup error: {e}"
        return result

    # Filter to records that start with v=DMARC1
    dmarc_records = [
        b"".join(rdata.strings).decode("utf-8", errors="replace")
        for rdata in answers
        if b"".join(rdata.strings).decode("utf-8", errors="replace").strip().lower().startswith("v=dmarc1")
    ]

    if not dmarc_records:
        result["dmarc_issue"] = "TXT record(s) present but none are valid DMARC (v=DMARC1)"
        return result

    if len(dmarc_records) > 1:
        result["dmarc_issue"] = (
            f"Multiple DMARC records found ({len(dmarc_records)}) — invalid per RFC 7489"
        )

    record = dmarc_records[0]
    tags = parse_dmarc_tags(record)

    result["dmarc_found"] = True
    result["dmarc_record"] = record
    result["dmarc_policy"] = tags.get("p", "")
    result["dmarc_subdomain_policy"] = tags.get("sp", tags.get("p", ""))
    result["dmarc_pct"] = tags.get("pct", "100")
    result["dmarc_rua"] = tags.get("rua", "")
    result["dmarc_ruf"] = tags.get("ruf", "")

    # Flag issues not already set (e.g. multiple records)
    if not result["dmarc_issue"]:
        policy = result["dmarc_policy"]
        if not policy:
            result["dmarc_issue"] = "No 'p=' tag found (malformed record)"
        elif policy == "none":
            result["dmarc_issue"] = "Policy is 'none' (monitor only, not enforced)"
        elif policy not in ("quarantine", "reject"):
            result["dmarc_issue"] = f"Unrecognized policy value: {policy}"

    return result

# ── SPF helpers ───────────────────────────────────────────────────────────────

def check_spf(domain: str, resolver: "dns.resolver.Resolver") -> dict:
    """
    Query <domain> TXT records for an SPF record (v=spf1).
    Returns a dict with keys: spf_found, spf_record, spf_issue, spf_ips.
    spf_ips contains only explicitly listed ip4:/ip6: addresses.
    """
    result = {
        "spf_found": False,
        "spf_record": "",
        "spf_issue": "",
        "spf_ips": [],
    }

    try:
        answers = resolver.resolve(domain, "TXT")
    except dns.resolver.NXDOMAIN:
        result["spf_issue"] = "No domain (NXDOMAIN)"
        return result
    except dns.resolver.NoAnswer:
        result["spf_issue"] = "No TXT record"
        return result
    except dns.exception.Timeout:
        result["spf_issue"] = "DNS query timed out"
        return result
    except Exception as e:
        result["spf_issue"] = f"DNS lookup error: {e}"
        return result

    spf_records = [
        b"".join(rdata.strings).decode("utf-8", errors="replace")
        for rdata in answers
        if b"".join(rdata.strings).decode("utf-8", errors="replace").strip().lower().startswith("v=spf1")
    ]

    if not spf_records:
        result["spf_issue"] = "No valid SPF record (v=spf1) found"
        return result

    if len(spf_records) > 1:
        result["spf_issue"] = (
            f"Multiple SPF records found ({len(spf_records)}) — invalid per RFC 7208"
        )

    result["spf_found"] = True
    result["spf_record"] = spf_records[0]

    # Extract only explicit ip4:/ip6: values (not 'include:' or 'a:' mechanismsmail-check
    result["spf_ips"] = [
        part.split(":", 1)[1]
        for part in result["spf_record"].split()
        if part.lower().startswith(("ip4:", "ip6:"))
    ]

    return result

# ── Generic DNS query ─────────────────────────────────────────────────────────

def query_record(domain: str, rtype: str, resolver: "dns.resolver.Resolver"):
    """
    Query any DNS record type for a domain.
    Returns (list_of_values, issue_string).
    MX records are returned as sorted hostname strings (without trailing dot).
    TXT records are returned as decoded strings.
    All others are returned as sorted lowercase strings.
    """
    try:
        answers = resolver.resolve(domain, rtype)
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], f"No {rtype} record"
    except dns.exception.Timeout:
        return [], "Query timed out"
    except Exception as e:
        return [], str(e)

    if rtype == "TXT":
        values = sorted(
            b"".join(r.strings).decode("utf-8", errors="replace") for r in answers
        )
    elif rtype == "MX":
        values = sorted(str(r.exchange).rstrip(".").lower() for r in answers)
    else:
        values = sorted(str(r).rstrip(".").lower() for r in answers)
    return values, ""

# ── Reverse DNS & ASN lookups ─────────────────────────────────────────────────

def reverse_dns(ip: str, timeout: float = 5.0) -> str:
    """
    PTR (reverse DNS) lookup for an IP address.
    Uses socket.setdefaulttimeout() so the underlying socket call is bounded —
    preventing hangs on slow or unresponsive PTR servers.
    Falls back to socket.gethostbyaddr if the dnspython PTR query fails.
    Returns the hostname string, or "" on failure.
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            pass
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def lookup_asn(ip: str, timeout: float = 8.0) -> str:
    """
    ASN lookup for an IP via RDAP (ipwhois library).
    Uses socket.setdefaulttimeout() so the HTTP calls inside ipwhois are bounded.
    Returns a string like 'AS16509 AMAZON-02 (US)', or an error/N/A string.
    """
    if not IPWHOIS_AVAILABLE:
        return "N/A (ipwhois not installed)"
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        result = IPWhois(ip).lookup_rdap(depth=1)
        parts = []
        if result.get("asn"):
            parts.append(f"AS{result['asn']}")
        if result.get("asn_description"):
            parts.append(result["asn_description"])
        if result.get("asn_country_code"):
            parts.append(f"({result['asn_country_code']})")
        return " ".join(parts) or "Unknown"
    except Exception as e:
        return f"Lookup failed: {e}"
    finally:
        socket.setdefaulttimeout(old_timeout)

# ── MX & Mail-A resolution ────────────────────────────────────────────────────

def get_mx_host_and_asn(mx_hosts: list, resolver: "dns.resolver.Resolver", domain: str = "") -> tuple:
    """
    Resolve MX hostnames → IPs → reverse-DNS + ASN.
    Self-hosted entries (MX host is a subdomain of the queried domain)
    are tagged with '(self-hosted)'.
    Returns (hostnames_str, asn_str) — semicolon-separated if multiple.
    """
    if not mx_hosts:
        return "-", "-"

    hostnames, asn_infos, seen_ips = [], [], set()

    for mx_host in mx_hosts:
        is_self = domain and (mx_host == domain or mx_host.endswith(f".{domain}"))
        label = " (self-hosted)" if is_self else ""

        mx_ips = []
        for rtype in ("A", "AAAA"):
            try:
                for rdata in resolver.resolve(mx_host, rtype):
                    ip = str(rdata)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        mx_ips.append(ip)
            except Exception:
                pass

        if mx_ips:
            for ip in mx_ips:
                rdns = reverse_dns(ip)
                hostnames.append(f"{rdns} [{ip}]{label}" if rdns else f"{ip}{label}")
                asn = lookup_asn(ip)
                if asn and asn not in asn_infos:
                    asn_infos.append(asn)
        else:
            hostnames.append(f"{mx_host}{label} (unresolved)")

    return (
        "; ".join(hostnames) or "-",
        "; ".join(asn_infos) or "-",
    )


def get_mail_a_records(domain: str, resolver: "dns.resolver.Resolver") -> tuple:
    """
    Always probe common mail-related subdomains (mail., smtp., mx., etc.)
    via A/AAAA lookups — regardless of whether MX records exist.

    Why: MX records often point to a third-party security gateway
    (Barracuda, Proofpoint, etc.) while the *real* mail server lives at
    mail.<domain> as a plain A record. Probing these subdomains exposes
    that actual server alongside the MX gateway.

    Returns (hostnames_str, asn_str) — semicolon-separated if multiple.
    """
    hostnames, asn_infos, seen_ips = [], [], set()

    for prefix in MAIL_SUBDOMAIN_PREFIXES:
        subdomain = f"{prefix}.{domain}"
        for rtype in ("A", "AAAA"):
            try:
                for rdata in resolver.resolve(subdomain, rtype):
                    ip = str(rdata)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        rdns = reverse_dns(ip)
                        hostnames.append(
                            f"{rdns} [{ip}] ({subdomain})" if rdns else f"{ip} ({subdomain})"
                        )
                        asn = lookup_asn(ip)
                        if asn and asn not in asn_infos:
                            asn_infos.append(asn)
            except Exception:
                pass

    return (
        "; ".join(hostnames) or "-",
        "; ".join(asn_infos) or "-",
    )

# ── Input helpers ─────────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    """Strip protocol, path, and port from a raw string to get a bare domain."""
    raw = raw.strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    raw = raw.split("/")[0]   # remove path
    raw = raw.split("@")[-1]  # handle user@domain
    return raw.lower()


def find_domain_column(fieldnames: list, requested: str) -> str:
    """
    Find the column that contains domain names in a CSV.
    Uses 'requested' if provided, otherwise tries common names, then falls
    back to the first column.
    """
    if requested:
        if requested not in fieldnames:
            sys.exit(f"Column '{requested}' not found. Available: {fieldnames}")
        return requested
    for candidate in ("domain", "domains", "Domain", "hostname", "host"):
        if candidate in fieldnames:
            return candidate
    return fieldnames[0]


def load_domains_from_file(path: str, requested_column: str) -> list:
    """
    Load a list of domains from a .txt or .csv file.
    TXT: one domain per line.
    CSV: auto-detects the domain column (or uses --column if given).
    """
    domains = []
    if path.lower().endswith(".txt"):
        with open(path, "r", encoding="utf-8-sig") as f:
            for line in f:
                raw = line.strip()
                if raw:
                    domains.append(clean_domain(raw))
    else:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                sys.exit("Input CSV has no header row.")
            col = find_domain_column(reader.fieldnames, requested_column)
            for row in reader:
                raw = (row.get(col) or "").strip()
                if raw:
                    domains.append(clean_domain(raw))
    return domains

# ── Excel output ──────────────────────────────────────────────────────────────

def write_excel(results: list, output_path: str):
    """
    Write results to a formatted .xlsx workbook.

    Columns:
      Domain | DMARC Found | DMARC Record | DMARC Policy | DMARC Sub-Policy |
      DMARC Pct | DMARC RUA/RUF | SPF Found | SPF Record | SPF IPs |
      SPF Qualifier | MX ASN | Mail A ASN

    Conditional formatting:
      - Red background on 'DMARC Found' when DMARC is missing.
      - Red background on 'DMARC Policy' when policy is 'none'.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "DMARC Results"

    # ── Styles ──
    black_fill  = PatternFill(fill_type='solid', fgColor='000000')
    red_fill    = PatternFill(fill_type='solid', fgColor='FF4444')
    hdr_font    = Font(name='Calibri', bold=True, color='FFFFFF', size=10)
    white_font  = Font(name='Calibri', color='FFFFFF', size=9)
    norm_font   = Font(name='Calibri', size=9)
    center_al   = Alignment(horizontal='center', vertical='center', wrap_text=True)
    left_al     = Alignment(horizontal='left',   vertical='center', wrap_text=True)
    thin_side   = Side(style='thin', color='000000')
    thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    col_labels = [
        'Domain',
        'DMARC Found', 'DMARC Record', 'DMARC Policy', 'DMARC Sub-Policy',
        'DMARC Pct', 'DMARC RUA/RUF',
        'SPF Found', 'SPF Record', 'SPF IPs', 'SPF Qualifier',
        'MX ASN',
        'Mail A ASN',
    ]

    # ── Header row ──
    for col_idx, label in enumerate(col_labels, start=1):
        cell = ws.cell(row=1, column=col_idx, value=label)
        cell.fill      = black_fill
        cell.font      = hdr_font
        cell.alignment = center_al
        cell.border    = thin_border

    col_map = {label: idx for idx, label in enumerate(col_labels, start=1)}

    # ── Data rows ──
    for row_idx, r in enumerate(results, start=2):
        rua_ruf  = ", ".join(filter(None, [r.get("dmarc_rua", ""), r.get("dmarc_ruf", "")]))
        spf_ips  = ", ".join(r.get("spf_ips", []))
        spf_qual = ""
        if r.get("spf_record"):
            m = re.search(r'[+\-~?]all', r["spf_record"], re.IGNORECASE)
            if m:
                spf_qual = m.group(0)

        dmarc_found  = r.get("dmarc_found", False)
        policy_none  = r.get("dmarc_policy", "").lower() == "none"

        row_values = [
            r.get("domain", ""),
            str(dmarc_found),
            r.get("dmarc_record", "")          if dmarc_found else "-",
            r.get("dmarc_policy", "")          if dmarc_found else "-",
            r.get("dmarc_subdomain_policy", "") if dmarc_found else "-",
            r.get("dmarc_pct", "")             if dmarc_found else "-",
            rua_ruf  or "-",
            str(r.get("spf_found", False)),
            r.get("spf_record", "") if r.get("spf_found") else "-",
            spf_ips  or "-",
            spf_qual or "-",
            r.get("mx_asn",     "-"),
            r.get("mail_a_asn", "-"),
        ]

        for col_idx, value in enumerate(row_values, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.alignment = left_al
            cell.border    = thin_border
            # Red highlight: missing DMARC
            if col_idx == col_map["DMARC Found"] and not dmarc_found:
                cell.fill = red_fill
                cell.font = white_font
            # Red highlight: policy is 'none'
            elif col_idx == col_map["DMARC Policy"] and policy_none:
                cell.fill = red_fill
                cell.font = white_font
            else:
                cell.font = norm_font

    # ── Auto-size columns (max width 80) ──
    for col in ws.columns:
        col_letter = col[0].column_letter
        max_len = max(
            (len(str(cell.value)) for cell in col if cell.value),
            default=0,
        )
        ws.column_dimensions[col_letter].width = min(max_len + 4, 80)

    ws.freeze_panes = "A2"  # Keep header visible while scrolling
    wb.save(output_path)
    print(f"{len(results)} row(s) written to Excel: {output_path}")

# ── Word / DOCX output ────────────────────────────────────────────────────────

def write_docx(results: list, output_path: str):
    """
    Write results to a formatted .docx Word document.
    Each domain gets:
      - A heading with the domain name.
      - A 4-column table: DMARC Config (left) | SPF Config (right).
      - A 2-column table: MX Info (gateway hostname + ASN).
    Red cell shading is applied for missing DMARC or policy='none'.
    """
    if docx is None:
        sys.exit("Missing dependency 'python-docx'.  Install:  pip install python-docx")

    from docx.shared import Pt, Inches, RGBColor
    from docx.oxml.ns import qn
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc = docx.Document()

    def set_cell_shading(cell, color_hex: str):
        """Apply a solid background colour to a table cell."""
        pr = cell._element.get_or_add_tcPr()
        shd = pr.makeelement(qn("w:shd"), {
            qn("w:val"):   "clear",
            qn("w:color"): "auto",
            qn("w:fill"):  color_hex,
        })
        pr.append(shd)

    def write_cell(cell, text: str, bold: bool = False,
                   font_size: int = 9, highlight_red: bool = False):
        """Write styled text into the first paragraph of a table cell."""
        if highlight_red:
            set_cell_shading(cell, "FF4444")
        run = cell.paragraphs[0].add_run(text)
        run.bold = bold
        run.font.size = Pt(font_size)
        run.font.name = "Calibri"
        if highlight_red:
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for r in results:
        # Domain heading (forced black — overrides theme colour)
        heading = doc.add_heading(f"Domain: {r['domain']}", level=1)
        for run in heading.runs:
            run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)

        # Compute derived values
        spf_qualifier = ""
        if r.get("spf_record"):
            m = re.search(r'[+\-~?]all', r["spf_record"], re.IGNORECASE)
            if m:
                spf_qualifier = m.group(0)

        dmarc_found   = r.get("dmarc_found", False)
        policy_none   = r.get("dmarc_policy", "").lower() == "none"
        rua_ruf = ", ".join(filter(None, [r.get("dmarc_rua", ""), r.get("dmarc_ruf", "")])) or "-"

        # Row definitions: (label, value, highlight_red)
        dmarc_rows = [
            ("Found",      str(dmarc_found),                                      not dmarc_found),
            ("Record",     r.get("dmarc_record", "-") if dmarc_found else "-",    False),
            ("Policy (p)", r.get("dmarc_policy", "-") if dmarc_found else "-",    policy_none),
            ("Rua/Ruf",    rua_ruf,                                                False),
        ]
        spf_rows = [
            ("Found",         str(r.get("spf_found", False)),                                False),
            ("Record",        r.get("spf_record", "-") if r.get("spf_found") else "-",       False),
            ("Extracted IPs", ", ".join(r.get("spf_ips", [])) or "-",                        False),
            ("Qualifier",     spf_qualifier or "-",                                           False),
        ]

        # ── DMARC / SPF side-by-side table ──
        max_rows = max(len(dmarc_rows), len(spf_rows))
        table = doc.add_table(rows=1 + max_rows, cols=4)
        table.style = "Table Grid"

        col_widths = [Inches(1.2), Inches(2.0), Inches(1.2), Inches(2.0)]
        for row_obj in table.rows:
            for i, w in enumerate(col_widths):
                row_obj.cells[i].width = w

        # Header
        dmarc_hdr = table.rows[0].cells[0].merge(table.rows[0].cells[1])
        set_cell_shading(dmarc_hdr, "000000")
        write_cell(dmarc_hdr, "DMARC Config", bold=True, font_size=10)
        for run in dmarc_hdr.paragraphs[0].runs:
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        dmarc_hdr.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        spf_hdr = table.rows[0].cells[2].merge(table.rows[0].cells[3])
        set_cell_shading(spf_hdr, "000000")
        write_cell(spf_hdr, "SPF Config", bold=True, font_size=10)
        for run in spf_hdr.paragraphs[0].runs:
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        spf_hdr.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Data rows
        for i in range(max_rows):
            data_row = table.rows[1 + i]
            if i < len(dmarc_rows):
                lbl, val, red = dmarc_rows[i]
                write_cell(data_row.cells[0], lbl, bold=True, highlight_red=red)
                write_cell(data_row.cells[1], val, highlight_red=red)
            if i < len(spf_rows):
                lbl, val, red = spf_rows[i]
                write_cell(data_row.cells[2], lbl, bold=True, highlight_red=red)
                write_cell(data_row.cells[3], val, highlight_red=red)

        # ── MX Info table ──
        mx_table = doc.add_table(rows=3, cols=2)
        mx_table.style = "Table Grid"
        for row_obj in mx_table.rows:
            row_obj.cells[0].width = Inches(1.5)
            row_obj.cells[1].width = Inches(5.0)

        mx_hdr = mx_table.rows[0].cells[0].merge(mx_table.rows[0].cells[1])
        set_cell_shading(mx_hdr, "333333")
        write_cell(mx_hdr, "MX Info", bold=True, font_size=10)
        for run in mx_hdr.paragraphs[0].runs:
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        mx_hdr.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        write_cell(mx_table.rows[1].cells[0], "MX Hostname", bold=True)
        write_cell(mx_table.rows[1].cells[1], r.get("mx_hostname", "-"))
        write_cell(mx_table.rows[2].cells[0], "MX ASN", bold=True)
        write_cell(mx_table.rows[2].cells[1], r.get("mx_asn", "-"))

        doc.add_paragraph()  # spacing between domains

    doc.save(output_path)
    print(f"{len(results)} domain(s) written to Word: {output_path}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Check DMARC, SPF, and MX configuration for a list of domains.\n"
            "Default output is Excel (.xlsx). Add --output-docx for a Word file too."
        )
    )
    parser.add_argument("input_file",
                        help="Path to a .txt (one domain per line) or .csv file")
    parser.add_argument("--column", default=None,
                        help="CSV column name containing domains (auto-detected if omitted)")
    parser.add_argument("--output", default="dmarc_results.xlsx",
                        help="Excel output path (default: dmarc_results.xlsx)")
    parser.add_argument("--output-docx", default=None, dest="output_docx",
                        help="Also write a Word document to this path (e.g. results.docx)")
    parser.add_argument("--nameserver", default=None,
                        help="Custom DNS resolver IP (e.g. 8.8.8.8)")
    args = parser.parse_args()

    # Ensure the Excel path ends in .xlsx
    excel_path = args.output
    if not excel_path.lower().endswith(".xlsx"):
        base = excel_path.rsplit(".", 1)[0] if "." in excel_path else excel_path
        excel_path = base + ".xlsx"

    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    if args.nameserver:
        resolver.nameservers = [args.nameserver]
    resolver.lifetime = 5
    resolver.timeout  = 5

    domains = load_domains_from_file(args.input_file, args.column)
    if not domains:
        sys.exit("No domains found in the input file.")

    print(f"Checking {len(domains)} domain(s) from '{args.input_file}'...\n")

    results = []
    for domain in domains:
        row = {"domain": domain}

        # Query MX, TXT, A — store raw values for internal use (DMARC/SPF/MX)
        record_values = {}
        for rtype in DEFAULT_RECORD_TYPES:
            values, _ = query_record(domain, rtype, resolver)
            record_values[rtype] = values

        # MX ASN — resolve MX hostnames → IPs → ASN (gateway/filter)
        print(f"  [{domain}] Resolving MX ASN...", end=" ", flush=True)
        mx_hostname, mx_asn = get_mx_host_and_asn(record_values.get("MX", []), resolver, domain)
        row["mx_hostname"] = mx_hostname  # kept for Word output
        row["mx_asn"]      = mx_asn
        print("done")

        # Mail A ASN — probe mail.*/smtp.* A records (real mail server)
        print(f"  [{domain}] Probing mail subdomain A records...", end=" ", flush=True)
        _, mail_a_asn = get_mail_a_records(domain, resolver)
        row["mail_a_asn"] = mail_a_asn
        print("done")

        # DMARC & SPF
        row.update(check_dmarc(domain, resolver))
        row.update(check_spf(domain, resolver))

        results.append(row)

        status = "OK" if row["dmarc_found"] and row["dmarc_policy"] in ("quarantine", "reject") else "REVIEW"
        print(f"  [{status:6}] {domain}\n")

    # Write outputs
    write_excel(results, excel_path)
    if args.output_docx:
        write_docx(results, args.output_docx)

    print(
        f"Done. Checked {len(domains)} domain(s).\n"
        f"  Excel : {excel_path}"
        + (f"\n  Word  : {args.output_docx}" if args.output_docx else "")
    )


if __name__ == "__main__":
    main()