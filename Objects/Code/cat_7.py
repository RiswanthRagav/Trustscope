#!/usr/bin/env python3
# cat_7.py — Domain Controller & Service Health (auto path + import-safe)
from __future__ import annotations

import os, json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timezone
from collections import defaultdict

# ========= Risk model (Category 7) =========
CHECK_META = {
    "fsmo_unreachable":   {"title": "FSMO not reachable",          "severity": "High", "score": 125},
    "dc_unreachable":     {"title": "DC not reachable",            "severity": "High", "score": 125},
    "replication_fail":   {"title": "Replication failures",        "severity": "High", "score": 125},
    "backup_overdue":     {"title": "Backup overdue",              "severity": "High", "score": 100},
}

# Expected JSON filenames
COMPUTERS_FILE = "nexora.local_computers.json"
DOMAINS_FILE   = "nexora.local_domains.json"
PRINT_MAX_DETAILS = 10


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


# ========= Checks =========
def check_fsmo_reachability(domains, replication_data):
    unreachable = replication_data.get("unreachable_fsmo", [])
    if not domains:  # no data
        return "UNKNOWN", [], True
    if unreachable:
        return "FAIL", [{"Object": "FSMO", "Detail": f"Unreachable={unreachable}"}], False
    return "PASS", [], False


def check_dc_reach(replication_data):
    unreachable = replication_data.get("unreachable_dcs", [])
    if unreachable:
        return "FAIL", [{"Object": "DC", "Detail": f"Unreachable={unreachable}"}], False
    return "PASS", [], False


def check_replication_failures(replication_data):
    fails = replication_data.get("replication_failures", [])
    if fails:
        return "FAIL", [{"Object": "Replication", "Detail": f"Failures={fails}"}], False
    return "PASS", [], False


def check_backup_age(backup_data):
    max_days = 7
    now = datetime.now(timezone.utc)
    issues = []
    for dc, ts in backup_data.items():
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (now - dt).days > max_days:
                issues.append(f"{dc} backup too old ({(now - dt).days}d)")
        except Exception:
            pass
    if issues:
        return "FAIL", [{"Object": "Backup", "Detail": x} for x in issues], False
    return "PASS", [], False


# ========= Main callable (safe to import) =========
def run_category7(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Category 7: Domain Controller & Service Health
    - Auto-resolves `input_dir` to .../Objects/Domain Data if None/invalid
    - Loads computers and domain JSON files
    - Simulates replication and backup data if missing
    Returns (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)

    computers = _load_json_list(base / COMPUTERS_FILE)
    domains   = _load_json_list(base / DOMAINS_FILE)

    # Placeholder simulated inputs (replace with real monitoring data if available)
    replication_data = {
        "unreachable_fsmo": ["WIN-DC01"],
        "unreachable_dcs": [],
        "replication_failures": []
    }
    backup_data = {
        "WIN-DC01": "2025-07-01T00:00:00Z",
        "WIN-DC02": "2025-08-25T00:00:00Z"
    }

    CHECKS = [
        ("fsmo_unreachable", lambda: check_fsmo_reachability(domains, replication_data)),
        ("dc_unreachable",   lambda: check_dc_reach(replication_data)),
        ("replication_fail", lambda: check_replication_failures(replication_data)),
        ("backup_overdue",   lambda: check_backup_age(backup_data)),
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

    # Totals
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # --- build text report ---
    lines = []
    lines.append("=== Category 7: Domain Controller & Service Health (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 7 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    for sev in ["High", "Medium", "Low"]:
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
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


# ========= CLI Test =========
if __name__ == "__main__":
    text, summary = run_category7(None)
    print(text)
    print("\nSummary:", summary)
