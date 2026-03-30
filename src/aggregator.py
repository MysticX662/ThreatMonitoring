"""
Threat Intelligence Aggregator
Fetches IOCs from URLhaus, CISA KEV, and ThreatFox, normalizes them into a
unified schema, defangs indicators, and writes static JSON to api/v1/.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "api" / "v1"
API_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Schema
# Each normalized record must match:
#   {
#     "ioc":         str  – the defanged indicator
#     "type":        str  – "url" | "ip" | "domain" | "hash" | "vulnerability"
#     "severity":    str  – "critical" | "high" | "medium" | "low" | "unknown"
#     "source":      str  – feed name
#     "description": str  – human-readable context
#     "timestamp":   str  – ISO-8601 UTC
#   }
# ---------------------------------------------------------------------------

SCHEMA_KEYS = ("ioc", "type", "severity", "source", "description", "timestamp")


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------

_URL_SCHEMES = re.compile(r"^https?://", re.IGNORECASE)
_IP_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:\d+)?$"
)


def defang(indicator: str) -> str:
    """Replace dots with [.] in URLs and IPs to prevent safety flags."""
    if not indicator:
        return indicator

    # Strip scheme so we can inspect the host
    bare = _URL_SCHEMES.sub("", indicator)

    # Always defang dots — safe for both IPs and domain-based URLs
    return indicator.replace(".", "[.]")


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def severity_from_confidence(confidence: int) -> str:
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def _safe_iso(raw: str | None) -> str:
    """Return raw value if it looks ISO-ish, otherwise now()."""
    if raw:
        return raw.strip()
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_urlhaus() -> list[dict]:
    print("[URLhaus] Fetching recent URLs …")
    try:
        resp = requests.post(URLHAUS_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[URLhaus] ERROR: {exc}", file=sys.stderr)
        return []

    records = []
    for entry in data.get("urls", []):
        raw_url = entry.get("url", "")
        threat = entry.get("threat", "malware_download")
        tags = ", ".join(entry.get("tags") or [])
        description = f"{threat}"
        if tags:
            description += f" | tags: {tags}"

        records.append({
            "ioc":         defang(raw_url),
            "type":        "url",
            "severity":    "high",
            "source":      "URLhaus",
            "description": description,
            "timestamp":   _safe_iso(entry.get("date_added")),
        })

    print(f"[URLhaus] {len(records)} records fetched.")
    return records


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV)
# ---------------------------------------------------------------------------

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def fetch_cisa_kev() -> list[dict]:
    print("[CISA KEV] Fetching known exploited vulnerabilities …")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[CISA KEV] ERROR: {exc}", file=sys.stderr)
        return []

    records = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        short_desc = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")

        description = f"{vendor} {product}: {short_desc}"
        if action:
            description += f" | Action: {action}"

        records.append({
            "ioc":         cve_id,           # CVEs are not defanged
            "type":        "vulnerability",
            "severity":    "critical",        # All KEV entries are actively exploited
            "source":      "CISA KEV",
            "description": description.strip(),
            "timestamp":   _safe_iso(vuln.get("dateAdded")),
        })

    print(f"[CISA KEV] {len(records)} records fetched.")
    return records


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox ioc_type values to our canonical types
THREATFOX_TYPE_MAP = {
    "url":        "url",
    "domain":     "domain",
    "ip:port":    "ip",
    "md5_hash":   "hash",
    "sha256_hash":"hash",
}


def fetch_threatfox() -> list[dict]:
    print("[ThreatFox] Fetching recent IOCs …")
    payload = {"query": "get_iocs", "days": 1}
    try:
        resp = requests.post(THREATFOX_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[ThreatFox] ERROR: {exc}", file=sys.stderr)
        return []

    if data.get("query_status") != "ok":
        print(
            f"[ThreatFox] Unexpected status: {data.get('query_status')}",
            file=sys.stderr,
        )
        return []

    records = []
    for entry in data.get("data") or []:
        raw_ioc = entry.get("ioc", "")
        ioc_type_raw = entry.get("ioc_type", "")
        ioc_type = THREATFOX_TYPE_MAP.get(ioc_type_raw, ioc_type_raw)
        confidence = int(entry.get("confidence_level", 0))
        malware = entry.get("malware", "")
        malware_alias = entry.get("malware_alias", "") or ""
        threat_type = entry.get("threat_type", "")
        tags = ", ".join(entry.get("tags") or [])

        description = f"{threat_type} | malware: {malware}"
        if malware_alias:
            description += f" ({malware_alias})"
        if tags:
            description += f" | tags: {tags}"

        # Defang URLs, IPs, and domains; leave hashes intact
        defanged = defang(raw_ioc) if ioc_type in ("url", "ip", "domain") else raw_ioc

        records.append({
            "ioc":         defanged,
            "type":        ioc_type,
            "severity":    severity_from_confidence(confidence),
            "source":      "ThreatFox",
            "description": description.strip(" |"),
            "timestamp":   _safe_iso(entry.get("first_seen")),
        })

    print(f"[ThreatFox] {len(records)} records fetched.")
    return records


# ---------------------------------------------------------------------------
# Merge + sort + slice
# ---------------------------------------------------------------------------

def merge_and_sort(all_records: list[dict], limit: int = 500) -> list[dict]:
    """Sort by timestamp descending, keep latest `limit` entries."""
    def _ts_key(r: dict) -> str:
        return r.get("timestamp", "")

    sorted_records = sorted(all_records, key=_ts_key, reverse=True)
    return sorted_records[:limit]


def validate_record(record: dict) -> bool:
    return all(k in record for k in SCHEMA_KEYS)


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"[write] {path.relative_to(REPO_ROOT)}  ({len(data)} records)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    all_records: list[dict] = []

    for fetch_fn in (fetch_urlhaus, fetch_cisa_kev, fetch_threatfox):
        records = fetch_fn()
        valid = [r for r in records if validate_record(r)]
        invalid_count = len(records) - len(valid)
        if invalid_count:
            print(
                f"  ⚠  {invalid_count} records dropped (missing schema fields)",
                file=sys.stderr,
            )
        all_records.extend(valid)

    print(f"\n[aggregator] Total raw records: {len(all_records)}")

    merged = merge_and_sort(all_records, limit=500)
    print(f"[aggregator] Writing {len(merged)} records to api/v1/latest.json")

    # api/v1/latest.json — top 500 across all sources
    write_json(API_DIR / "latest.json", merged)

    # api/v1/ips.json — IP-type IOCs only
    ips = [r for r in merged if r["type"] == "ip"]
    write_json(API_DIR / "ips.json", ips)

    # api/v1/vulnerabilities.json — vulnerability (CVE) entries only
    vulns = [r for r in merged if r["type"] == "vulnerability"]
    write_json(API_DIR / "vulnerabilities.json", vulns)

    print("\n[aggregator] Done.")


if __name__ == "__main__":
    main()
