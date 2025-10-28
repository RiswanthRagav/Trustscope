#!/usr/bin/env python3
# cat_12.py — Computer & Domain Management (import-safe, path-agnostic)
from __future__ import annotations

import os, json
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Tuple

COMPUTERS_FILE = "nexora.local_computers.json"
DOMAINS_FILE   = "nexora.local_domains.json"
PRINT_MAX_DETAILS = 10

# ========= Risk model (Category 12) =========
CHECK_META = {
    "computers_with_bitlocker":      {"title": "Computers with BitLocker keys",              "severity": "Info",   "score": 0},
    "domain_controllers":            {"title": "Domain Controllers identified",              "severity": "Info",   "score": 0},
    "kerberos_config":               {"title": "Kerberos configuration present",             "severity": "Medium", "score": 24},
    "non_admins_can_add_computers":  {"title": "Non-admin users can add computers to domain","severity": "Medium", "score": 24},
    "recently_backed_up":            {"title": "Computers backed up within 7 days",          "severity": "Low",    "score": 12},
    "up_to_date_computers":          {"title": "Computers up-to-date within 30 days",        "severity": "Low",    "score": 12},
    "smb_signing_required":          {"title": "SMB signing required",                       "severity": "Medium", "score": 24},
    "spooler_enabled":               {"title": "Spooler service enabled on computers",       "severity": "Medium", "score": 18},
    "ldap_signature_required":       {"title": "LDAP signature required",                    "severity": "Medium", "score": 24},
    "channel_binding_enforced":      {"title": "Channel binding enforced",                   "severity": "Medium", "score": 24},
}

# ========= Helpers =========
def _resolve_dir(input_dir: str | os.PathLike | None) -> Path:
    if input_dir:
        p = Path(input_dir)
        return p if p.is_dir() else p.parent
    # fallback to working dir
    return Path(".").resolve()

def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]
    return data if isinstance(data, list) else []

def _prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

# ========= Checks =========
def _check_computers_with_bitlocker(computers):
    items = []
    for comp in computers:
        if _prop(comp, "bitlockerkeys"):
            items.append({"Object": _prop(comp,"name"), "Detail":"BitLocker key present"})
    # Info: treat presence as PASS (informational), but still return items
    return ("PASS", items)

def _check_domain_controllers(computers):
    items = []
    for comp in computers:
        dn = (_prop(comp,"distinguishedname","") or "").lower()
        if "ou=domain controllers" in dn:
            items.append({"Object":_prop(comp,"name"), "Detail":"Domain Controller OU"})
    return ("PASS", items) if items else ("UNKNOWN", [])

def _check_kerberos_config(kerberos_config=None):
    if kerberos_config is None:
        return ("UNKNOWN", [])
    return ("PASS", [{"Object":"Domain","Detail":"Kerberos config provided"}])

def _check_non_admins_can_add_computers(domains):
    for d in domains:
        for ace in d.get("Aces",[]) or []:
            rn = (ace.get("RightName","") or "").lower()
            principal = (ace.get("PrincipalSID","") or "").lower()
            if rn == "add workstation to domain" and (
                "authenticated users" in principal or principal.endswith("\\users") or principal == "users"
            ):
                return ("FAIL",[{"Object":"Domain","Detail":f"ACE grants '{rn}' to '{principal}'"}])
    return ("PASS", [])

def _check_recently_backed_up(computers):
    items=[]
    now = datetime.now(timezone.utc).timestamp()
    threshold = now - 7*24*3600
    for comp in computers:
        lb = _prop(comp,"lastbackup",0)
        if lb and lb > threshold:
            items.append({"Object":_prop(comp,"name"),"Detail":"Recent backup"})
    return ("PASS", items) if items else ("FAIL", [])

def _check_up_to_date(computers):
    items=[]
    now = datetime.now(timezone.utc).timestamp()
    threshold = now - 30*24*3600
    for comp in computers:
        lu = _prop(comp,"lastupdate",0)
        if lu and lu > threshold:
            items.append({"Object":_prop(comp,"name"),"Detail":"Up to date"})
    return ("PASS", items) if items else ("FAIL", [])

def _check_smb_signing(domains):
    for d in domains:
        for ace in d.get("Aces",[]) or []:
            if (ace.get("RightName","") or "").lower() == "require smb signing":
                return ("PASS",[{"Object":"Domain","Detail":"Require SMB signing ACE present"}])
    return ("FAIL", [])

def _check_spooler_enabled(computers):
    issues=[]
    for comp in computers:
        for svc in comp.get("Services",[]) or []:
            if (svc.get("Name","") or "").lower()=="spooler" and (svc.get("StartMode","") or "").lower()=="automatic":
                issues.append({"Object":_prop(comp,"name"),"Detail":"Spooler service Automatic"})
    return ("FAIL",issues) if issues else ("PASS", [])

def _check_ldap_signature(domains):
    for d in domains:
        for ace in d.get("Aces",[]) or []:
            if (ace.get("RightName","") or "").lower()=="require ldap signature":
                return ("PASS",[{"Object":"Domain","Detail":"LDAP signature required"}])
    return ("FAIL", [])

def _check_channel_binding(domains):
    for d in domains:
        for ace in d.get("Aces",[]) or []:
            if (ace.get("RightName","") or "").lower()=="enforce channel binding":
                return ("PASS",[{"Object":"Domain","Detail":"Channel binding enforced"}])
    return ("FAIL", [])

# ========= Public entry =========
def run_category12(input_dir: str | os.PathLike | None) -> Tuple[str, Dict[str, Any]]:
    base = _resolve_dir(input_dir)
    computers = _load_json_list(base / COMPUTERS_FILE)
    domains   = _load_json_list(base / DOMAINS_FILE)

    CHECKS = [
        ("computers_with_bitlocker",      lambda: _check_computers_with_bitlocker(computers)),
        ("domain_controllers",            lambda: _check_domain_controllers(computers)),
        ("kerberos_config",               lambda: _check_kerberos_config(None)),  # inject real config if available
        ("non_admins_can_add_computers",  lambda: _check_non_admins_can_add_computers(domains)),
        ("recently_backed_up",            lambda: _check_recently_backed_up(computers)),
        ("up_to_date_computers",          lambda: _check_up_to_date(computers)),
        ("smb_signing_required",          lambda: _check_smb_signing(domains)),
        ("spooler_enabled",               lambda: _check_spooler_enabled(computers)),
        ("ldap_signature_required",       lambda: _check_ldap_signature(domains)),
        ("channel_binding_enforced",      lambda: _check_channel_binding(domains)),
    ]

    results: List[Dict[str, Any]] = []
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    info_items: List[Dict[str, Any]] = []  # keep Info PASS items visible
    unknown_items: List[Dict[str, Any]] = []

    for key, fn in CHECKS:
        status, details = fn()
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

        if meta["severity"] == "Info":
            if details:  # show Info results even on PASS
                info_items.append(rec)
        else:
            if status == "FAIL":
                buckets[meta["severity"]].append(rec)
            if status == "UNKNOWN":
                unknown_items.append(rec)
                buckets[meta["severity"]].append(rec)  # show unknowns in their severity section

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)

    # Risk: only from FAIL/UNKNOWN (Info has score 0 anyway)
    category_risk_total = sum(r["score"] for r in results if r["status"] in ("FAIL","UNKNOWN"))
    risk_by_severity = {"High":0,"Medium":0,"Low":0,"Info":0}
    for r in results:
        if r["status"] in ("FAIL","UNKNOWN"):
            risk_by_severity[r["severity"]] = risk_by_severity.get(r["severity"],0) + r["score"]

    # Build report text
    lines: List[str] = []
    lines.append("=== Category 12: Computer & Domain Management (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 12 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity.get('High',0)}")
    lines.append(f"  - Medium risk points: {risk_by_severity.get('Medium',0)}")
    lines.append(f"  - Low risk points:    {risk_by_severity.get('Low',0)}")
    lines.append(f"  - Info items:         {len(info_items)}\n")

    for sev in ["High","Medium","Low"]:
        items = buckets.get(sev, [])
        if not items: lines.append(f"{sev}: (none)"); continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    # Info section (always shown if there are items)
    if info_items:
        lines.append("Info:")
        for r in info_items:
            lines.append(f"  - {r['title']} -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    if unknown_items:
        lines.append("Non-passing (UNKNOWN) checks (counted as FAIL):")
        for r in unknown_items:
            lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    summary = {
        "High":   len(buckets.get("High",[])),
        "Medium": len(buckets.get("Medium",[])),
        "Low":    len(buckets.get("Low",[])),
        "Info":   len(info_items),
        "TotalFails": failed_total,
        "Unknown":    unknown_total,
        "RiskScore":  category_risk_total,
    }
    return report_text, summary


# Optional: quick CLI test
if __name__ == "__main__":
    txt, summ = run_category12(None)  # looks for files in current directory
    print(txt)
    print("\nSummary:", summ)
