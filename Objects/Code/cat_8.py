#!/usr/bin/env python3
# cat_8.py — System & Disk Health (auto path + import-safe)
from __future__ import annotations

import os, json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from collections import Counter, defaultdict

# ========= Risk model (Category 8) =========
CHECK_META = {
    "os_partition_low":   {"title": "OS partition low space",   "severity": "Low", "score": 18},
    "ntds_partition_low": {"title": "NTDS partition low space", "severity": "Low", "score": 18},
}

COMPUTERS_FILE = "nexora.local_computers.json"

PRINT_MAX_DETAILS = 10
OS_MIN_FREE_PERCENT   = 15
NTDS_MIN_FREE_PERCENT = 15


# ========= Path resolver =========
def _resolve_input_dir_prefer_domain_data(base_hint: Optional[str | Path]) -> Path:
    """
    Resolve the folder that contains exported Nexora JSONs.
    Priority:
      1) base_hint if exists
      2) this file's .../Objects/Domain Data (and variants)
      3) fallback to .../Objects/data or .../Objects
    """
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent

    code_dir = Path(__file__).resolve().parent   # .../Objects/Code
    objects_dir = code_dir.parent                # .../Objects

    candidates = [
        objects_dir / "Domain Data",
        objects_dir / "DomainData",
        objects_dir / "domain data",
        objects_dir / "data",
        objects_dir,
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return objects_dir


# ========= helpers =========
def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return data if isinstance(data, list) else []


def prop(d: Dict[str, Any] | None, key: str, default=None):
    if not isinstance(d, dict):
        return default
    return (d.get("Properties") or {}).get(key, default)


# ========= checks =========
def check_os_partition(computers):
    issues = []
    for c in computers:
        dn = (prop(c, "distinguishedname", "") or "").lower()
        if "ou=domain controllers" not in dn:
            continue
        name = prop(c, "name", "<DC>")
        free = prop(c, "os_partition_free_percent")
        if free is None:
            issues.append({"Object": name, "Detail": "OS free space unknown"})
        elif free < OS_MIN_FREE_PERCENT:
            issues.append({"Object": name, "Detail": f"OS free {free}% < {OS_MIN_FREE_PERCENT}%"})
    if not computers:
        return "UNKNOWN", [], True
    return ("FAIL", issues, False) if issues else ("PASS", [], False)


def check_ntds_partition(computers):
    issues = []
    for c in computers:
        dn = (prop(c, "distinguishedname", "") or "").lower()
        if "ou=domain controllers" not in dn:
            continue
        name = prop(c, "name", "<DC>")
        free = prop(c, "ntds_partition_free_percent")
        if free is None:
            issues.append({"Object": name, "Detail": "NTDS free space unknown"})
        elif free < NTDS_MIN_FREE_PERCENT:
            issues.append({"Object": name, "Detail": f"NTDS free {free}% < {NTDS_MIN_FREE_PERCENT}%"})
    if not computers:
        return "UNKNOWN", [], True
    return ("FAIL", issues, False) if issues else ("PASS", [], False)


# ========= public API (Streamlit-safe) =========
def run_category8(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Category 8: System & Disk Health
    - Auto-resolves `input_dir` to .../Objects/Domain Data if None/invalid
    - Loads computers JSON and checks partition health
    Returns (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)
    computers = _load_json_list(base / COMPUTERS_FILE)

    CHECKS = [
        ("os_partition_low",   lambda: check_os_partition(computers)),
        ("ntds_partition_low", lambda: check_ntds_partition(computers)),
    ]

    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}
    unknown_items = []

    for key, fn in CHECKS:
        status, details, is_unknown = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    # Summaries
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # Build text report
    lines = []
    lines.append("=== Category 8: System & Disk Health (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 8 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    for sev in ["Low", "Medium", "High"]:
        items = failed_by_sev.get(sev, [])
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d['Object']} - {d['Detail']}")
            if r["fail_items"] > PRINT_MAX_DETAILS:
                lines.append(f"      ... and {r['fail_items'] - PRINT_MAX_DETAILS} more")
        lines.append("")

    lines.append("Non-passing (UNKNOWN) checks:")
    for r in unknown_items:
        lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "TotalFails": failed_total,
        "RiskScore": category_risk_total,
        "Unknown": unknown_total,
    }

    return report_text, summary


# ========= CLI test =========
if __name__ == "__main__":
    text, summary = run_category8(None)
    print(text)
    print("\nSummary:", summary)
