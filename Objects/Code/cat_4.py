#!/usr/bin/env python3
import os, json, xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple
from collections import Counter, defaultdict

# ========= CONFIG =========
INPUT_DIR   = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
ALL_GPOS_XML = r"C:\Users\LENOVO\OneDrive\Desktop\AllGPOs.xml"
DDP_XML      = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPolicy.xml"

# Which admin principals must be denied? (case-insensitive substring match)
ADMIN_PRINCIPALS = [
    "domain admins",
    "enterprise admins",
]

PRINT_MAX_DETAILS = 10

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

# ========= helpers =========
def parse_user_rights_from_gpo_xml(xml_path: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not os.path.exists(xml_path):
        return out
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {
            "gp":  "http://www.microsoft.com/GroupPolicy/Settings",
            "sec": "http://www.microsoft.com/GroupPolicy/Settings/Security",
        }
        # <sec:Privilege> style
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
        # <sec:UserRightsAssignment><sec:Right Name="">
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

# ========= load and parse =========
rights_ddp   = parse_user_rights_from_gpo_xml(DDP_XML)
rights_all   = parse_user_rights_from_gpo_xml(ALL_GPOS_XML)
rights_merged = merge_rights_maps(rights_ddp, rights_all)

def check_right_enabled_for_admins(key: str) -> Tuple[str, List[Dict[str, str]], bool]:
    """Return (status, details, unknown_flag). unknown_flag=True means
       we also show this check in the UNKNOWN summary (Cat1–3 style)."""
    ura = RIGHTS[key]
    members = rights_merged.get(ura)

    if members is None:
        details = [{"Object": "GPO/User Rights",
                    "Detail": f"{ura} not found in provided GPO XMLs; deny right not configured"}]
        # FAIL + mark as unknown (so it appears in the UNKNOWN list)
        return ("FAIL", details, True)

    ok, matched = has_admin_principal(members, [p.lower() for p in ADMIN_PRINCIPALS])
    if ok:
        return ("PASS", [], False)
    else:
        details = [{"Object": "User Rights Assignment",
                    "Detail": f"{ura} present but no admin principals; members={members}"}]
        return ("FAIL", details, False)

# ========= run all =========
CHECKS = [
    ("deny_network", check_right_enabled_for_admins),
    ("deny_service", check_right_enabled_for_admins),
    ("deny_rdp",     check_right_enabled_for_admins),
    ("deny_batch",   check_right_enabled_for_admins),
]

def main():
    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}

    for key, fn in CHECKS:
        status, details, unknown_flag = fn(key)
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,            # PASS / FAIL
            "unknown": unknown_flag,     # for the UNKNOWN summary list
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    # ===== runtime report =====
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r.get("unknown", False))

    by_sev_counts = Counter()
    for r in results:
        if r["status"] == "FAIL":
            by_sev_counts[r["severity"]] += 1

    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    print("\n=== Category 4: Admin Restrictions – Workstations & Servers (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 4 Total Risk Score: {category_risk_total}")
    print(f"  - High risk points:   {risk_by_severity['High']}")
    print(f"  - Medium risk points: {risk_by_severity['Medium']}")
    print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    print("Failures by severity:")
    print(f"  High  : {by_sev_counts.get('High', 0)}")
    print(f"  Medium: {by_sev_counts.get('Medium', 0)}")
    print(f"  Low   : {by_sev_counts.get('Low', 0)}\n")

    def print_failed_block(sev: str, max_details: int = PRINT_MAX_DETAILS):
        items = failed_by_sev.get(sev, [])
        if not items:
            print(f"{sev}: (none)")
            return
        print(f"{sev}:")
        for r in items:
            print(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            details = r["details"]
            if max_details and len(details) > max_details:
                for d in details[:max_details]:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
                print(f"      ... and {len(details)-max_details} more")
            else:
                for d in details:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
        print()

    print_failed_block("Medium")

    print("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r.get("unknown", False):
            print(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")
    print()

if __name__ == "__main__":
    main()
def run_category4(input_dir: str):
    """
    Wrapper for Category 4: Administrator Account Restrictions – Workstations & Member Servers
    Returns (report_text, summary_dict)
    """

    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}
    unknown_items = []

    # Run all defined checks
    for key, fn in CHECKS:
        status, details, is_unknown = fn(key)
        meta = CHECK_META[key]

        rec_status = status  # keep FAIL/PASS
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": rec_status,
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)

        if rec_status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)

    # Risk score totals
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # ---------------- Build the text report ----------------
    lines = []
    lines.append("=== Category 4: Administrator Account Restrictions – Workstations & Member Servers (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 4 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    def print_block(sev):
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            return
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            for d in r["details"]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    print_block("High")
    print_block("Medium")
    print_block("Low")

    lines.append("Non-passing (UNKNOWN) checks:")
    for r in unknown_items:
        lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    # ---------------- Build the summary dict ----------------
    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "TotalFails": failed_total,
        "RiskScore": category_risk_total,
    }

    return report_text, summary
