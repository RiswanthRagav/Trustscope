#!/usr/bin/env python3
# cat_4.py — Admin Restrictions (auto path + import-safe)
from __future__ import annotations

import os, json, xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter, defaultdict

# ========= Risk model (Category 4) =========
CHECK_META = {
    "deny_network": {"title": "Deny access from network not enabled",         "severity": "Medium", "score": 48},
    "deny_service": {"title": "Deny log on as service not enabled",           "severity": "Medium", "score": 48},
    "deny_rdp":     {"title": "Deny RDP not enabled",                         "severity": "Medium", "score": 48},
    "deny_batch":   {"title": "Deny log on as batch job not enabled",         "severity": "Medium", "score": 36},
}

# Windows policy names → URA constants used in GPO
RIGHTS = {
    "deny_network": "SeDenyNetworkLogonRight",
    "deny_service": "SeDenyServiceLogonRight",
    "deny_rdp":     "SeDenyRemoteInteractiveLogonRight",
    "deny_batch":   "SeDenyBatchLogonRight",
}

# Which admin principals must be denied? (case-insensitive substring match)
ADMIN_PRINCIPALS = [
    "domain admins",
    "enterprise admins",
]

PRINT_MAX_DETAILS = 10

# ========= path helpers (no top-level I/O) =========
def _resolve_input_dir_prefer_domain_data(base_hint: Optional[str | Path]) -> Path:
    """
    Resolve the folder that contains your exported XML/JSON dumps.
    Priority:
      1) base_hint if it exists
      2) this file's .../Objects/Domain Data (and fallbacks)
      3) .../Objects/data
      4) .../Objects
    """
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent

    code_dir = Path(__file__).resolve().parent           # .../Objects/Code
    objects_dir = code_dir.parent                        # .../Objects

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

def _pick_xml(base: Path, preferred_name: str, loose_glob: str) -> Optional[Path]:
    """
    Try the exact filename first (in base), then a loose glob (e.g., '*AllGPO*.xml').
    """
    exact = base / preferred_name
    if exact.exists():
        return exact
    matches = list(base.glob(loose_glob))
    return matches[0] if matches else None

# ========= XML parsing =========
def parse_user_rights_from_gpo_xml(xml_path: Path | None) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not xml_path or not xml_path.exists():
        return out
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {
            "gp":  "http://www.microsoft.com/GroupPolicy/Settings",
            "sec": "http://www.microsoft.com/GroupPolicy/Settings/Security",
        }
        # <sec:Privilege>
        for priv in root.findall(".//sec:SecuritySettings//sec:Privilege", ns):
            name = (priv.findtext("sec:Name", default="", namespaces=ns) or "").strip()
            if not name:
                continue
            members = []
            for m in priv.findall(".//sec:Member", ns):
                txt = (m.text or "").strip()
                if txt:
                    members.append(txt)
            if members:
                out.setdefault(name, [])
                for mem in members:
                    if mem not in out[name]:
                        out[name].append(mem)

        # <sec:UserRightsAssignment><sec:Right Name="...">
        for right in root.findall(".//sec:SecuritySettings//sec:UserRightsAssignment//sec:Right", ns):
            name = (right.get("Name") or "").strip()
            if not name:
                continue
            members = []
            for m in right.findall(".//sec:Member", ns):
                txt = (m.text or "").strip()
                if txt:
                    members.append(txt)
            if members:
                out.setdefault(name, [])
                for mem in members:
                    if mem not in out[name]:
                        out[name].append(mem)
    except Exception:
        pass
    return out

def merge_rights_maps(*maps: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    for mp in maps:
        for k, vlist in (mp or {}).items():
            merged.setdefault(k, [])
            for v in vlist:
                if v not in merged[k]:
                    merged[k].append(v)
    return merged

def has_admin_principal(members: List[str], admin_principals_lower: List[str]) -> Tuple[bool, List[str]]:
    matched = []
    for m in members:
        lm = m.lower()
        for token in admin_principals_lower:
            if token in lm:
                matched.append(m)
                break
    return (len(matched) > 0, matched)

# ========= core check runner (no prints; safe for Streamlit) =========
def _run_checks_with_rights(rights_merged: Dict[str, List[str]]) -> Tuple[str, Dict[str, Any]]:
    def check_right_enabled_for_admins(key: str) -> Tuple[str, List[Dict[str, str]], bool]:
        """Return (status, details, unknown_flag)."""
        ura = RIGHTS[key]
        members = rights_merged.get(ura)

        if members is None:
            details = [{"Object": "GPO/User Rights",
                        "Detail": f"{ura} not found in provided GPO XMLs; deny right not configured"}]
            return ("FAIL", details, True)

        ok, _matched = has_admin_principal(members, [p.lower() for p in ADMIN_PRINCIPALS])
        if ok:
            return ("PASS", [], False)
        else:
            details = [{"Object": "User Rights Assignment",
                        "Detail": f"{ura} present but no admin principals; members={members}"}]
            return ("FAIL", details, False)

    CHECKS = [
        ("deny_network", check_right_enabled_for_admins),
        ("deny_service", check_right_enabled_for_admins),
        ("deny_rdp",     check_right_enabled_for_admins),
        ("deny_batch",   check_right_enabled_for_admins),
    ]

    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}
    unknown_items: List[Dict[str, Any]] = []

    for key, fn in CHECKS:
        status, details, unknown_flag = fn(key)
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,            # PASS / FAIL
            "unknown": unknown_flag,     # to expose as 'UNKNOWN'
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if unknown_flag:
            unknown_items.append(rec)

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)

    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")

    # ---------- build text report ----------
    lines: List[str] = []
    lines.append("=== Category 4: Admin Restrictions – Workstations & Servers (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 4 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    def _add_block(sev: str):
        items = failed_by_sev.get(sev, [])
        if not items:
            lines.append(f"{sev}: (none)")
            return
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            for d in r["details"]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    _add_block("Medium")  # only Medium checks exist here

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

# ========= public API =========
def run_category4(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Wrapper for Category 4: Administrator Account Restrictions – Workstations & Member Servers
    - Auto-resolves `input_dir` to .../Objects/Domain Data (with fallbacks) if None/invalid
    - Looks for 'DefaultDomainPolicy.xml' and 'AllGPOs.xml' in that folder (loose globs as fallback)
    Returns: (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)

    ddp_xml  = _pick_xml(base, "DefaultDomainPolicy.xml", "*DefaultDomainPolicy*.xml")
    all_xml  = _pick_xml(base, "AllGPOs.xml",            "*AllGPO*.xml")

    rights_ddp = parse_user_rights_from_gpo_xml(ddp_xml)
    rights_all = parse_user_rights_from_gpo_xml(all_xml)
    rights_merged = merge_rights_maps(rights_ddp, rights_all)

    return _run_checks_with_rights(rights_merged)

# ========= CLI test (optional) =========
if __name__ == "__main__":
    text, summary = run_category4(None)
    print(text)
