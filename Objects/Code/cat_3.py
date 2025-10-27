# cat_3.py — Privileged Accounts & Group Membership (safe for Streamlit import)
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple, Set, Optional
from datetime import datetime, timezone, timedelta
import json
from collections import Counter, defaultdict

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
    "kerberoastable":       {"title": "Accounts vulnerable to Kerberoasting",                       "severity": "High",   "score": 100},
    "asreproastable":       {"title": "Accounts vulnerable to ASRepRoasting",                       "severity": "High",   "score": 80},
    "priv_groups_undesired":{"title": "Privileged groups contain undesired members",                "severity": "High",   "score": 80},
    "admin_can_be_delegated":{"title": "Admin accounts can be delegated",                           "severity": "High",   "score": 80},
    "in_schema_admins":     {"title": "Accounts in Schema Admins",                                   "severity": "High",   "score": 80},
    "users_in_privesc":     {"title": "Users in Privesc group",                                      "severity": "High",   "score": 80},
    "admin_not_sensitive":  {"title": "Admin 'Sensitive & Cannot be Delegated' disabled",            "severity": "High",   "score": 80},
    "admin_no_smartcard":   {"title": "Admin Smart card not required",                               "severity": "High",   "score": 64},
    "admins_not_protected": {"title": "Admin accounts not in Protected Users group",                 "severity": "High",   "score": 64},
    "builtin_admin_used":   {"title": "Native Administrator account used recently",                  "severity": "High",   "score": 64},
    # Medium
    "priv_users_not_default":{"title": "Privileged users not set to defaults",                      "severity": "Medium", "score": 48},
    "pre2k_members":        {"title": "Pre-Windows 2000 Compatible Access group members",           "severity": "Medium", "score": 48},
    # Low
    "had_admin_before":     {"title": "Accounts that had admin rights in the past",                 "severity": "Low",    "score": 36},
    "gmsa_misconfig":       {"title": "GMSA misconfigurations",                                     "severity": "Low",    "score": 36},
}

# Tunables
ADMIN_RECENT_DAYS = 90

# ========= helpers (no top-level I/O) =========
def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return data if isinstance(data, list) else []

def _prop(d: Dict[str, Any] | None, k: str, default=None):
    if not isinstance(d, dict):
        return default
    return (d.get("Properties") or {}).get(k, default)

def _to_index(objs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {o.get("ObjectIdentifier"): o for o in objs if isinstance(o, dict)}

def _group_member_sids(group_obj: Dict[str, Any] | None) -> List[str]:
    if not group_obj:
        return []
    return [m.get("ObjectIdentifier") for m in (group_obj.get("Members") or []) if isinstance(m, dict)]

def _find_group_by_sam(groups: List[Dict[str, Any]], sam: str) -> Dict[str, Any] | None:
    sam = sam.lower()
    for g in groups:
        if (_prop(g, "samaccountname", "") or "").lower() == sam:
            return g
    return None

def _filetime_to_datetime(v) -> datetime | None:
    if v in (None, 0, "0"):
        return None
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
    # Try ISO8601
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None

# ========= main callable (safe to import) =========
def run_category3(
    input_dir: str | Path,
    desired_members_sids: Optional[Set[str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Privileged Accounts & Group Membership
    - Loads JSON from `input_dir` (expects nexora.local_users.json and nexora.local_groups.json)
    - desired_members_sids: optional baseline of allowed SIDs for DA/EA/SA (enables 'priv_groups_undesired')
    Returns: (report_text, summary_dict)
    """
    base = Path(input_dir)
    users_path  = base / "nexora.local_users.json"
    groups_path = base / "nexora.local_groups.json"

    users  = _load_json_list(users_path)
    groups = _load_json_list(groups_path)

    idx_users  = _to_index(users)
    idx_groups = _to_index(groups)

    # Privileged groups we care about
    g_domain_admins     = _find_group_by_sam(groups, "Domain Admins")
    g_enterprise_admins = _find_group_by_sam(groups, "Enterprise Admins")
    g_schema_admins     = _find_group_by_sam(groups, "Schema Admins")
    g_protected_users   = _find_group_by_sam(groups, "Protected Users")

    domain_admin_sids     = set(_group_member_sids(g_domain_admins))
    enterprise_admin_sids = set(_group_member_sids(g_enterprise_admins))
    schema_admin_sids     = set(_group_member_sids(g_schema_admins))
    protected_user_sids   = set(_group_member_sids(g_protected_users))

    all_admin_sids: Set[str] = domain_admin_sids | enterprise_admin_sids | schema_admin_sids

    # ========= checks (close over loaded data) =========
    def check_kerberoastable():
        bad = []
        for u in users:
            if not _prop(u, "enabled", False):
                continue
            spns = _prop(u, "serviceprincipalnames") or []
            if spns:
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": f"{len(spns)} SPN(s) present"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_asreproastable():
        bad = []
        for u in users:
            if not _prop(u, "enabled", False):
                continue
            if _prop(u, "dontreqpreauth", False):
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": "DONT_REQ_PREAUTH=True"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_privileged_groups_undesired():
        """
        If desired_members_sids is None/empty -> UNKNOWN.
        Otherwise FAIL on any DA/EA/SA member not in desired set.
        """
        if not desired_members_sids:
            return ("UNKNOWN", [{"Object":"Policy","Detail":"No desired member SID list provided"}])
        bad = []
        for label, sids in [("Domain Admins", domain_admin_sids),
                            ("Enterprise Admins", enterprise_admin_sids),
                            ("Schema Admins", schema_admin_sids)]:
            for sid in sids:
                if sid not in desired_members_sids:
                    who = _prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else _prop(idx_groups.get(sid, {}), "name", sid)
                    bad.append({"Object": who, "Detail": f"Member of {label} but not in desired list"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_admin_can_be_delegated():
        """
        FAIL if an admin (DA/EA/SA member) is delegatable:
          - AllowedToDelegate list not empty  OR
          - 'sensitive' flag is False
        """
        bad = []
        for sid in all_admin_sids:
            u = idx_users.get(sid)
            if not u:  # nested groups may appear
                continue
            sensitive = bool(_prop(u, "sensitive", False))
            allowed   = u.get("AllowedToDelegate") or []
            if (not sensitive) or allowed:
                bad.append({"Object": _prop(u, "name", sid),
                            "Detail": f"sensitive={sensitive}, AllowedToDelegate={len(allowed)}"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_in_schema_admins():
        if not schema_admin_sids:
            return ("PASS", [])
        details = []
        for sid in schema_admin_sids:
            who = _prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else _prop(idx_groups.get(sid, {}), "name", sid)
            details.append({"Object": who, "Detail": "Member of Schema Admins"})
        return ("FAIL", details)

    def check_users_in_privesc():
        """
        Heuristic: any group whose samAccountName or name contains 'privesc'
        """
        pr_members = []
        for g in groups:
            gname = (_prop(g, "samaccountname", "") or _prop(g, "name", "") or "").lower()
            if "privesc" in gname:
                for m in g.get("Members") or []:
                    sid = m.get("ObjectIdentifier")
                    who = _prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else _prop(idx_groups.get(sid, {}), "name", sid)
                    pr_members.append({"Object": who, "Detail": f"Member of {_prop(g,'name','<group>')}"})
        return ("FAIL", pr_members) if pr_members else ("PASS", [])

    def check_admin_not_sensitive():
        """
        FAIL for any admin account (DA/EA/SA member) that is NOT 'sensitive' (ACCOUNT_NOT_DELEGATED).
        """
        bad = []
        for sid in all_admin_sids:
            u = idx_users.get(sid)
            if not u:
                continue
            if not bool(_prop(u, "sensitive", False)):
                bad.append({"Object": _prop(u, "name", sid), "Detail": "Account not marked 'sensitive' (cannot be delegated)"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_admin_no_smartcard():
        """
        FAIL for any admin account that does NOT require smart card.
        """
        bad = []
        for sid in all_admin_sids:
            u = idx_users.get(sid)
            if not u:
                continue
            if not bool(_prop(u, "smartcardrequired", False)):
                bad.append({"Object": _prop(u, "name", sid), "Detail": "smartcardRequired=False"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_admins_not_in_protected_users():
        """
        FAIL for any admin (DA/EA/SA member) not in 'Protected Users'.
        """
        if g_protected_users is None:
            return ("UNKNOWN", [{"Object":"Directory","Detail":"'Protected Users' group not found"}])
        bad = []
        for sid in all_admin_sids:
            if sid not in protected_user_sids:
                who = _prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else _prop(idx_groups.get(sid, {}), "name", sid)
                bad.append({"Object": who, "Detail": "Admin not in 'Protected Users'"})
        return ("FAIL", bad) if bad else ("PASS", [])

    def check_builtin_admin_used_recently():
        """
        FAIL if the built-in 'Administrator' has lastLogonTimestamp within ADMIN_RECENT_DAYS.
        """
        admin_user = None
        for u in users:
            if (_prop(u, "samaccountname","") or "").lower() == "administrator":
                admin_user = u
                break
        if not admin_user:
            return ("UNKNOWN", [{"Object":"Directory", "Detail":"Built-in Administrator account not found"}])

        ts = _prop(admin_user, "lastlogontimestamp")
        dt = _filetime_to_datetime(ts)
        if not dt:
            return ("UNKNOWN", [{"Object":_prop(admin_user,"name","Administrator"), "Detail":"No parsable lastLogonTimestamp"}])

        days = (datetime.now(timezone.utc) - dt).days
        if days <= ADMIN_RECENT_DAYS:
            return ("FAIL", [{"Object":_prop(admin_user,"name","Administrator"),
                              "Detail": f"lastLogonTimestamp={dt.date()} ({days} days ago)"}])
        return ("PASS", [])

    def check_priv_users_not_default():
        # Needs explicit baseline of default ACLs/rights for each privileged account.
        return ("UNKNOWN", [{"Object":"Policy","Detail":"Needs baseline of default privileged user permissions/ACLs"}])

    def check_pre2k_members():
        g = _find_group_by_sam(groups, "Pre-Windows 2000 Compatible Access")
        if not g:
            return ("PASS", [])
        members = _group_member_sids(g)
        if not members:
            return ("PASS", [])
        details = []
        for sid in members:
            who = _prop(idx_users.get(sid, {}), "name", sid) if sid in idx_users else _prop(idx_groups.get(sid, {}), "name", sid)
            details.append({"Object": who, "Detail": "Member of Pre-Windows 2000 Compatible Access"})
        return ("FAIL", details)

    def check_had_admin_before():
        # Historical question; without change history, mark UNKNOWN.
        return ("UNKNOWN", [{"Object":"Directory","Detail":"Needs historical admin-rights evidence (change logs)"}])

    def check_gmsa_misconfig():
        # Requires policy/ACL evaluation on gMSA usage; mark UNKNOWN.
        return ("UNKNOWN", [{"Object":"Policy","Detail":"Needs gMSA policy/ACL evaluation beyond current JSON"}])

    CHECKS = [
        # High
        ("kerberoastable",         check_kerberoastable),
        ("asreproastable",         check_asreproastable),
        ("priv_groups_undesired",  check_privileged_groups_undesired),
        ("admin_can_be_delegated", check_admin_can_be_delegated),
        ("in_schema_admins",       check_in_schema_admins),
        ("users_in_privesc",       check_users_in_privesc),
        ("admin_not_sensitive",    check_admin_not_sensitive),
        ("admin_no_smartcard",     check_admin_no_smartcard),
        ("admins_not_protected",   check_admins_not_in_protected_users),
        ("builtin_admin_used",     check_builtin_admin_used_recently),
        # Medium
        ("priv_users_not_default", check_priv_users_not_default),  # UNKNOWN
        ("pre2k_members",          check_pre2k_members),
        # Low
        ("had_admin_before",       check_had_admin_before),        # UNKNOWN
        ("gmsa_misconfig",         check_gmsa_misconfig),          # UNKNOWN
    ]

    # ========= execute checks (no prints; return text blob) =========
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

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r["status"] == "UNKNOWN")

    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")

    # ---------- build text report ----------
    lines: List[str] = []
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

    def _add_block(sev: str):
        items = failed_by_sev.get(sev, [])
        if not items:
            lines.append(f"{sev}: (none)")
            return
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} object(s)")
            for d in r["details"]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    _add_block("High")
    _add_block("Medium")
    _add_block("Low")

    report_text = "\n".join(lines)

    summary = {
        "Category": "Privileged Accounts & Group Membership",
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "Unknown": unknown_total,
        "TotalFails": failed_total,
        "RiskScore": category_risk_total,
    }

    return report_text, summary
