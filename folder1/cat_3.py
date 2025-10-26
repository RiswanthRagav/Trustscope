#!/usr/bin/env python3
import json, os
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple, Set
from datetime import datetime, timezone, timedelta

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"  # <-- change if needed
USERS_FILE   = "nexora.local_users.json"
GROUPS_FILE  = "nexora.local_groups.json"

# "recent" usage window for the built-in Administrator account
ADMIN_RECENT_DAYS = 90

# ========= Risk model (Category 3) =========
# High Risks
# 1.  Accounts vulnerable to Kerberoasting (100)
# 2.  Accounts vulnerable to ASRepRoasting (80)
# 3.  Privileged groups contain undesired members (80)
# 4.  Admin accounts can be delegated (80)
# 5.  Accounts in Schema Admins (80)
# 6.  Users in Privesc group (80)
# 7.  Admin “Sensitive & Cannot be Delegated” disabled (80)
# 8.  Admin Smart card not required (64)
# 9.  Admin accounts not in Protected Users group (64)
# 10. Native Administrator account used recently (64)
# Medium Risks
# 1.  Privileged users not set to defaults (48)  -> UNKNOWN (needs ACL baseline)
# 2.  Pre-Windows 2000 Access group members (48)
# Low Risks
# 1.  Accounts that had admin rights in the past (36) -> UNKNOWN (needs history)
# 2.  GMSA misconfigurations (36) -> UNKNOWN (needs policy/ACLs)

CHECK_META = {
    # High
    "kerberoastable":      {"title": "Accounts vulnerable to Kerberoasting",                       "severity": "High",   "score": 100},
    "asreproastable":      {"title": "Accounts vulnerable to ASRepRoasting",                       "severity": "High",   "score": 80},
    "priv_groups_undesired":{"title": "Privileged groups contain undesired members",               "severity": "High",   "score": 80},
    "admin_can_be_delegated":{"title": "Admin accounts can be delegated",                          "severity": "High",   "score": 80},
    "in_schema_admins":    {"title": "Accounts in Schema Admins",                                  "severity": "High",   "score": 80},
    "users_in_privesc":    {"title": "Users in Privesc group",                                     "severity": "High",   "score": 80},
    "admin_not_sensitive": {"title": "Admin 'Sensitive & Cannot be Delegated' disabled",           "severity": "High",   "score": 80},
    "admin_no_smartcard":  {"title": "Admin Smart card not required",                              "severity": "High",   "score": 64},
    "admins_not_protected":{"title": "Admin accounts not in Protected Users group",                "severity": "High",   "score": 64},
    "builtin_admin_used":  {"title": "Native Administrator account used recently",                 "severity": "High",   "score": 64},
    # Medium
    "priv_users_not_default":{"title": "Privileged users not set to defaults",                     "severity": "Medium", "score": 48},
    "pre2k_members":       {"title": "Pre-Windows 2000 Compatible Access group members",           "severity": "Medium", "score": 48},
    # Low
    "had_admin_before":    {"title": "Accounts that had admin rights in the past",                 "severity": "Low",    "score": 36},
    "gmsa_misconfig":      {"title": "GMSA misconfigurations",                                     "severity": "Low",    "score": 36},
}

# ========= helpers =========
def pjoin(*a): return os.path.join(*a)

def load_json_list(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    if isinstance(data, list):
        return data
    return []

def prop(d: Dict[str, Any], k: str, default=None):
    return (d.get("Properties") or {}).get(k, default)

def to_index(objs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {o.get("ObjectIdentifier"): o for o in objs if isinstance(o, dict)}

def group_member_sids(group_obj: Dict[str, Any]) -> List[str]:
    if not group_obj: return []
    return [m.get("ObjectIdentifier") for m in (group_obj.get("Members") or [])]

def find_group_by_sam(groups: List[Dict[str, Any]], sam: str) -> Dict[str, Any] | None:
    sam = sam.lower()
    for g in groups:
        if (prop(g, "samaccountname", "") or "").lower() == sam:
            return g
    return None

def filetime_to_datetime(v) -> datetime | None:
    if v in (None, 0, "0"): return None
    try:
        iv = int(v)
        if iv > 10**14:
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return epoch + timedelta(microseconds=iv/10)  # 100ns ticks -> µs
        elif iv > 10**12:
            return datetime.fromtimestamp(iv/1000.0, tz=timezone.utc)
        elif iv > 10**9:
            return datetime.fromtimestamp(iv, tz=timezone.utc)
    except Exception:
        pass
    # Try ISO
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None

# ========= load data =========
users  = load_json_list(pjoin(INPUT_DIR, USERS_FILE))
groups = load_json_list(pjoin(INPUT_DIR, GROUPS_FILE))
idx_users  = to_index(users)
idx_groups = to_index(groups)

# ========= derive useful sets =========
# Privileged groups we care about
g_domain_admins    = find_group_by_sam(groups, "Domain Admins")
g_enterprise_admins= find_group_by_sam(groups, "Enterprise Admins")
g_schema_admins    = find_group_by_sam(groups, "Schema Admins")
g_protected_users  = find_group_by_sam(groups, "Protected Users")

domain_admin_sids     = set(group_member_sids(g_domain_admins))
enterprise_admin_sids = set(group_member_sids(g_enterprise_admins))
schema_admin_sids     = set(group_member_sids(g_schema_admins))
protected_user_sids   = set(group_member_sids(g_protected_users))

all_admin_sids: Set[str] = domain_admin_sids | enterprise_admin_sids | schema_admin_sids

# ========= checks =========
def check_kerberoastable():
    bad = []
    for u in users:
        if not prop(u, "enabled", False):
            continue
        spns = prop(u, "serviceprincipalnames") or []
        if spns:
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": f"{len(spns)} SPN(s) present"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_asreproastable():
    bad = []
    for u in users:
        if not prop(u, "enabled", False):
            continue
        if prop(u, "dontreqpreauth", False):
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": "DONT_REQ_PREAUTH=True"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_privileged_groups_undesired(desired_members_sids: Set[str] | None = None):
    """
    If desired_members_sids is None or empty, we can't validate: return UNKNOWN with reason.
    Otherwise fail for any member of Domain/Enterprise/Schema Admins not in desired list.
    """
    if not desired_members_sids:
        return ("UNKNOWN", [{"Object":"Policy","Detail":"No desired member SID list provided"}])

    bad = []
    for label, sids in [("Domain Admins", domain_admin_sids),
                        ("Enterprise Admins", enterprise_admin_sids),
                        ("Schema Admins", schema_admin_sids)]:
        for sid in sids:
            if sid not in desired_members_sids:
                who = prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else prop(idx_groups.get(sid, {}), "name", sid)
                bad.append({"Object": who, "Detail": f"Member of {label} but not in desired list"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_admin_can_be_delegated():
    """
    Fail if an admin (member of DA/EA/SA) is *delegatable*:
      - AllowedToDelegate list not empty  OR
      - 'sensitive' flag is False
    """
    bad = []
    for sid in all_admin_sids:
        u = idx_users.get(sid)
        if not u:  # sometimes nested groups
            continue
        sensitive = bool(prop(u, "sensitive", False))
        allowed   = u.get("AllowedToDelegate") or []
        if (not sensitive) or allowed:
            bad.append({"Object": prop(u, "name", sid),
                        "Detail": f"sensitive={sensitive}, AllowedToDelegate={len(allowed)}"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_in_schema_admins():
    if not schema_admin_sids:
        return ("PASS", [])
    details = []
    for sid in schema_admin_sids:
        who = prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else prop(idx_groups.get(sid, {}), "name", sid)
        details.append({"Object": who, "Detail": "Member of Schema Admins"})
    return ("FAIL", details)

def check_users_in_privesc():
    """
    Heuristic: any group whose samAccountName or name contains 'privesc'
    """
    pr_members = []
    for g in groups:
        gname = (prop(g, "samaccountname", "") or prop(g, "name", "") or "").lower()
        if "privesc" in gname:
            for m in g.get("Members") or []:
                sid = m.get("ObjectIdentifier")
                who = prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else prop(idx_groups.get(sid, {}), "name", sid)
                pr_members.append({"Object": who, "Detail": f"Member of {prop(g,'name','<group>')}"})
    return ("FAIL", pr_members) if pr_members else ("PASS", [])

def check_admin_not_sensitive():
    """
    Fail for any admin account (DA/EA/SA member) that is NOT 'sensitive' (ACCOUNT_NOT_DELEGATED).
    """
    bad = []
    for sid in all_admin_sids:
        u = idx_users.get(sid)
        if not u: continue
        if not bool(prop(u, "sensitive", False)):
            bad.append({"Object": prop(u, "name", sid), "Detail": "Account not marked 'sensitive' (cannot be delegated)"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_admin_no_smartcard():
    """
    Fail for any admin account that does NOT require smart card.
    """
    bad = []
    for sid in all_admin_sids:
        u = idx_users.get(sid)
        if not u: continue
        if not bool(prop(u, "smartcardrequired", False)):
            bad.append({"Object": prop(u, "name", sid), "Detail": "smartcardRequired=False"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_admins_not_in_protected_users():
    """
    Fail for any admin (DA/EA/SA member) not in 'Protected Users'.
    """
    if g_protected_users is None:
        return ("UNKNOWN", [{"Object":"Directory","Detail":"'Protected Users' group not found"}])
    bad = []
    for sid in all_admin_sids:
        if sid not in protected_user_sids:
            who = prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else prop(idx_groups.get(sid, {}), "name", sid)
            bad.append({"Object": who, "Detail": "Admin not in 'Protected Users'"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_builtin_admin_used_recently():
    """
    Fail if the built-in Administrator account has a lastLogonTimestamp within ADMIN_RECENT_DAYS.
    We try to locate by SAM 'Administrator' (case-insensitive).
    """
    admin_user = None
    for u in users:
        if (prop(u, "samaccountname","") or "").lower() == "administrator":
            admin_user = u
            break
    if not admin_user:
        return ("UNKNOWN", [{"Object":"Directory", "Detail":"Built-in Administrator account not found"}])

    ts = prop(admin_user, "lastlogontimestamp")
    dt = filetime_to_datetime(ts)
    if not dt:
        return ("UNKNOWN", [{"Object":prop(admin_user,"name","Administrator"), "Detail":"No parsable lastLogonTimestamp"}])

    days = (datetime.now(timezone.utc) - dt).days
    if days <= ADMIN_RECENT_DAYS:
        return ("FAIL", [{"Object":prop(admin_user,"name","Administrator"),
                          "Detail": f"lastLogonTimestamp={dt.date()} ({days} days ago)"}])
    return ("PASS", [])

def check_priv_users_not_default():
    """
    Needs explicit baseline of default ACLs/rights for each privileged account.
    Without that, mark UNKNOWN (we cannot infer from BloodHound JSON alone).
    """
    return ("UNKNOWN", [{"Object":"Policy","Detail":"Needs baseline of default privileged user permissions/ACLs"}])

def check_pre2k_members():
    g = find_group_by_sam(groups, "Pre-Windows 2000 Compatible Access")
    if not g:
        return ("PASS", [])
    members = group_member_sids(g)
    if not members:
        return ("PASS", [])
    details = []
    for sid in members:
        who = prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else prop(idx_groups.get(sid, {}), "name", sid)
        details.append({"Object": who, "Detail": "Member of Pre-Windows 2000 Compatible Access"})
    return ("FAIL", details)

def check_had_admin_before():
    """
    Historical question. Without change history, mark UNKNOWN.
    """
    return ("UNKNOWN", [{"Object":"Directory","Detail":"Needs historical admin-rights evidence (change logs)"}])

def check_gmsa_misconfig():
    """
    Requires policy/ACL evaluation on gMSA usage and SPN/service bindings. Mark UNKNOWN.
    """
    # We can list gMSA-like accounts (very rough heuristic), but not judge 'misconfig' safely.
    return ("UNKNOWN", [{"Object":"Policy","Detail":"Needs gMSA policy/ACL evaluation beyond current JSON"}])

# ========= run =========
CHECKS = [
    # High
    ("kerberoastable",        check_kerberoastable),
    ("asreproastable",        check_asreproastable),
    ("priv_groups_undesired", lambda: check_privileged_groups_undesired(desired_members_sids=None)),  # pass a set of SIDs to enable
    ("admin_can_be_delegated",check_admin_can_be_delegated),
    ("in_schema_admins",      check_in_schema_admins),
    ("users_in_privesc",      check_users_in_privesc),
    ("admin_not_sensitive",   check_admin_not_sensitive),
    ("admin_no_smartcard",    check_admin_no_smartcard),
    ("admins_not_protected",  check_admins_not_in_protected_users),
    ("builtin_admin_used",    check_builtin_admin_used_recently),
    # Medium
    ("priv_users_not_default",check_priv_users_not_default),  # UNKNOWN
    ("pre2k_members",         check_pre2k_members),
    # Low
    ("had_admin_before",      check_had_admin_before),        # UNKNOWN
    ("gmsa_misconfig",        check_gmsa_misconfig),          # UNKNOWN
]

def main():
    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}

    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,           # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    # ===== runtime report =====
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r["status"] == "UNKNOWN")

    by_sev_counts = Counter()
    for r in results:
        if r["status"] == "FAIL":
            by_sev_counts[r["severity"]] += 1

    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    print("\n=== Category 3: Privileged Accounts & Group Membership (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 3 Total Risk Score: {category_risk_total}")
    print(f"  - High risk points:   {risk_by_severity['High']}")
    print(f"  - Medium risk points: {risk_by_severity['Medium']}")
    print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    print("Failures by severity:")
    print(f"  High  : {by_sev_counts.get('High', 0)}")
    print(f"  Medium: {by_sev_counts.get('Medium', 0)}")
    print(f"  Low   : {by_sev_counts.get('Low', 0)}\n")

    def print_failed_block(sev: str, max_details: int = 10):
        items = failed_by_sev.get(sev, [])
        if not items:
            print(f"{sev}: (none)")
            return
        print(f"{sev}:")
        for r in items:
            print(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} object(s)")
            details = r["details"]
            if max_details and len(details) > max_details:
                for d in details[:max_details]:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
                print(f"      ... and {len(details)-max_details} more")
            else:
                for d in details:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
        print()

    print_failed_block("High")
    print_failed_block("Medium")
    print_failed_block("Low")

    print("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r["status"] == "UNKNOWN":
            print(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

if __name__ == "__main__":
    main()
    
def run_category3(input_dir: str):
    """
    Wrapper for Category 3: Privileged Accounts & Group Membership
    Returns (report_text, summary_dict)
    """

    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}

    # Run all defined checks
    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,   # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r["status"] == "UNKNOWN")

    # Risk score totals
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # ---------------- Build the text report ----------------
    lines = []
    lines.append("=== Category 3: Privileged Accounts & Group Membership (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 3 Total Risk Score: {category_risk_total}")
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
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} object(s)")
            for d in r["details"]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    print_block("High")
    print_block("Medium")
    print_block("Low")

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
