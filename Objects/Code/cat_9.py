#!/usr/bin/env python3
# cat_9.py — Account & Audit Monitoring (auto path + import-safe)
from __future__ import annotations

import os, json
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict

# ========= Risk model (Category 9) =========
INACTIVITY_DAYS_THRESHOLD = 90
PRINT_MAX_DETAILS = 10

CHECK_META = {
    # High risks
    "audit_policy_misconfig": {"title": "Audit policy misconfigured",               "severity": "High",   "score": 32},
    "audit_mgmt_issues":      {"title": "Audit & policy management issues",         "severity": "High",   "score": 32},
    "default_pw_policy_bad":  {"title": "Default password policy misconfig",        "severity": "High",   "score": 32},
    "weak_pw_gpo":            {"title": "Weak GPO with password settings",          "severity": "High",   "score": 32},
    # Medium risks
    "inactive_accounts":      {"title": f"Inactive accounts > {INACTIVITY_DAYS_THRESHOLD} days", "severity": "Medium", "score": 24},
    "gpo_misconfig_ou":       {"title": "GPO misconfig by OU",                      "severity": "Medium", "score": 18},
    # Low risks
    "locked_accounts":        {"title": "Locked accounts",                          "severity": "Low",    "score": 12},
}

USERS_FILE = "nexora.local_users.json"
GPO_FILE   = "nexora.local_gpos.json"
# If present in the data dir, we’ll read this (shape: {"misconfigured": true/false, ...})
AUDIT_FILE_CANDIDATES = ["audit_policy.json", "audit.json", "AuditPolicy.json"]


# ========= Path resolver =========
def _resolve_input_dir_prefer_domain_data(base_hint: Optional[str | Path]) -> Path:
    """
    Resolve folder that contains exported Nexora JSONs.
    Priority:
      1) base_hint (dir) if provided
      2) this file's .../Objects/Domain Data (and variants)
      3) .../Objects/data then .../Objects
    """
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent

    code_dir = Path(__file__).resolve().parent      # .../Objects/Code
    objects_dir = code_dir.parent                   # .../Objects

    for c in [objects_dir / "Domain Data",
              objects_dir / "DomainData",
              objects_dir / "domain data",
              objects_dir / "data",
              objects_dir]:
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

def _load_json_obj_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else None

def prop(d: Dict[str, Any] | None, key: str, default=None):
    if not isinstance(d, dict):
        return default
    return (d.get("Properties") or {}).get(key, default)

def _filetime_to_datetime(v) -> Optional[datetime]:
    """
    Parse AD timestamps commonly seen in exports:
    - Windows FILETIME (100ns ticks since 1601) when very large
    - Epoch ms/s
    - ISO8601 string
    """
    if v in (None, 0, "0", ""):
        return None
    try:
        iv = int(v)
        if iv > 10**14:  # FILETIME
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return epoch + timedelta(microseconds=iv/10)
        if iv > 10**12:  # epoch ms
            return datetime.fromtimestamp(iv/1000.0, tz=timezone.utc)
        if iv > 10**9:   # epoch s
            return datetime.fromtimestamp(iv, tz=timezone.utc)
    except Exception:
        pass
    # Try string
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None


# ========= checks =========
def check_locked_accounts(users: List[Dict[str, Any]]):
    bad = [
        {"Object": prop(u, "name", "<user>"), "Detail": "lockedout=True"}
        for u in users if bool(prop(u, "lockedout", False))
    ]
    return ("FAIL", bad, False) if bad else ("PASS", [], False)

def check_inactive_accounts(users: List[Dict[str, Any]]):
    now = datetime.now(timezone.utc)
    threshold_days = INACTIVITY_DAYS_THRESHOLD
    bad = []
    saw_any = False
    for u in users:
        ts = prop(u, "lastlogontimestamp")
        dt = _filetime_to_datetime(ts)
        if dt:
            saw_any = True
            if (now - dt).days > threshold_days:
                bad.append({
                    "Object": prop(u, "name", "<user>"),
                    "Detail": f"lastLogonTimestamp={dt.date()} (> {threshold_days} days)"
                })
    if not saw_any:
        # No usable timestamps -> unknown rather than pass
        return ("UNKNOWN", [], True)
    return ("FAIL", bad, False) if bad else ("PASS", [], False)

def check_audit_policy(audit_data: Optional[Dict[str, Any]]):
    if audit_data is None:
        return ("UNKNOWN", [], True)
    if audit_data.get("misconfigured"):
        return ("FAIL", [{"Object": "AuditPolicy", "Detail": "Audit policy misconfigured"}], False)
    return ("PASS", [], False)

def check_default_pw_policy(gpos: List[Dict[str, Any]]):
    """
    Heuristic: if we find any GPO that looks like a password policy and its name hints "weak",
    flag as FAIL; if we find none at all -> UNKNOWN (needs more data).
    """
    bad = []
    found_any_pw_gpo = False
    for g in gpos:
        name = (prop(g, "name", "") or "").lower()
        if any(tok in name for tok in ["password", "pwd", "default domain policy"]):
            found_any_pw_gpo = True
            if "weak" in name or "legacy" in name:
                bad.append({"Object": prop(g, "name"), "Detail": "Weak/legacy password GPO naming signal"})
    if not found_any_pw_gpo:
        return ("UNKNOWN", [], True)
    return ("FAIL", bad, False) if bad else ("PASS", [], False)

def check_gpo_misconfig_ou(gpos: List[Dict[str, Any]]):
    bad = []
    for g in gpos:
        dn = prop(g, "distinguishedname", "") or ""
        name = (prop(g, "name", "") or "").lower()
        if "ou=" in dn.lower() and "misconfig" in name:
            bad.append({"Object": dn, "Detail": f"GPO {prop(g,'name')} flagged as misconfig (by name)"})
    return ("FAIL", bad, False) if bad else ("PASS", [], False)


# ========= shared runner =========
def _run_checks(checks: List[Tuple[str, callable]]):
    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}
    unknown_items = []

    for key, fn in checks:
        status, details, is_unknown = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key, "title": meta["title"], "severity": meta["severity"],
            "score": meta["score"], "status": status, "unknown": is_unknown,
            "fail_items": len(details), "details": details
        }
        results.append(rec)

        # Count unknowns in failure groupings so they appear in the UI by severity
        if status == "FAIL" or is_unknown:
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    return results, failed_by_sev, unknown_items


def _build_text_report(results, failed_by_sev, unknown_items) -> str:
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL" or r.get("unknown"))
    unknown_total = len(unknown_items)
    by_sev_counts = Counter(r["severity"] for r in results if r["status"] == "FAIL" or r.get("unknown"))
    # Risk only counts true FAILs
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    lines = []
    lines.append("=== Category 9: Account & Audit Monitoring (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 9 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {by_sev_counts.get('High', 0)}")
    lines.append(f"  Medium: {by_sev_counts.get('Medium', 0)}")
    lines.append(f"  Low   : {by_sev_counts.get('Low', 0)}\n")

    for sev in ["High", "Medium", "Low"]:
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            note = " -> needs additional data" if r.get("unknown") else ""
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s){note}")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")
    return "\n".join(lines)


# ========= public API (Streamlit-safe) =========
def run_category9(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Category 9: Account & Audit Monitoring
    - Auto-resolves `input_dir` to .../Objects/Domain Data if None/invalid
    - Loads users / gpos and optional audit policy JSON if present
    Returns (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)
    users = _load_json_list(base / USERS_FILE)
    gpos  = _load_json_list(base / GPO_FILE)

    audit_data = None
    for cand in AUDIT_FILE_CANDIDATES:
        found = base / cand
        if found.exists():
            audit_data = _load_json_obj_if_exists(found)
            break

    CHECKS = [
        ("locked_accounts",        lambda: check_locked_accounts(users)),
        ("inactive_accounts",      lambda: check_inactive_accounts(users)),
        ("audit_policy_misconfig", lambda: check_audit_policy(audit_data)),
        ("audit_mgmt_issues",      lambda: check_audit_policy(audit_data)),
        ("default_pw_policy_bad",  lambda: check_default_pw_policy(gpos)),
        ("weak_pw_gpo",            lambda: check_default_pw_policy(gpos)),
        ("gpo_misconfig_ou",       lambda: check_gpo_misconfig_ou(gpos)),
    ]

    results, failed_by_sev, unknown_items = _run_checks(CHECKS)
    report_text = _build_text_report(results, failed_by_sev, unknown_items)

    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "TotalFails": sum(1 for r in results if r["status"] == "FAIL" or r.get("unknown")),
        "RiskScore": sum(r["score"] for r in results if r["status"] == "FAIL"),
        "Unknown": len(unknown_items),
    }
    return report_text, summary


# ========= CLI test =========
if __name__ == "__main__":
    text, summary = run_category9(None)  # auto-locate Domain Data
    print(text)
    print("\nSummary:", summary)
