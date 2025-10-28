#!/usr/bin/env python3
# cat_13.py — Privilege & Trust Management (import-safe)
from __future__ import annotations

import os, json, re
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from collections import Counter, defaultdict

# Filenames expected inside input_dir
CONTAINERS_FILE = "nexora.local_containers.json"
USERS_FILE      = "nexora.local_users.json"
GROUPS_FILE     = "nexora.local_groups.json"
COMPUTERS_FILE  = "nexora.local_computers.json"
GPOS_FILE       = "nexora.local_gpos.json"
DOMAINS_FILE    = "nexora.local_domains.json"

PRINT_MAX_DETAILS = 10  # 0 = unlimited

# Heuristics for “safe” vs “risky” principals
ALLOWED_ADMIN_TOKENS = [
    "domain admins", "enterprise admins", "administrators", "schema admins",
    "system", "exchange organization administrators", "group policy creator owners"
]
RISKY_PRINCIPAL_TOKENS = [
    "authenticated users", "domain users", "users", "everyone",
    "guests", "pre-windows 2000", "anonymous", "remote desktop users"
]

# SID patterns
ADMIN_SID_PATTERNS = [
    r"^S-1-5-32-544$",               # Builtin Administrators
    r".*-512$",                      # Domain Admins
    r".*-519$",                      # Enterprise Admins
    r".*-518$",                      # Schema Admins
]
RISKY_SID_PATTERNS = [
    r"^S-1-1-0$",                    # Everyone
    r"^S-1-5-11$",                   # Authenticated Users
    r"^S-1-5-7$",                    # Anonymous
    r"^S-1-5-32-545$",               # Users
    r"^S-1-5-32-546$",               # Guests
    r".*-513$",                      # Domain Users
]

# ======== Risk model (scores) ========
CHECK_META = {
    "registry_rights_misconfig":     {"title":"Registry access rights misconfigured",                 "severity":"Medium", "score":24},
    "container_delegations_insecure":{"title":"Control delegations by container insecure",            "severity":"High",   "score":40},
    "privilege_rights_excessive":    {"title":"Privilege rights (SeDebug, SeBackup, etc.) excessive", "severity":"High",   "score":40},
    "auth_policy_silos_misconfig":   {"title":"Authentication policy silos misconfigured",            "severity":"Medium", "score":24},
    "trust_accounts_misused":        {"title":"Trust accounts for delegation misused",                "severity":"High",   "score":40},
    "rbac_misconfigured":            {"title":"Computers with RBAC misconfigured",                    "severity":"Medium", "score":18},
    "dns_create_unauthorized":       {"title":"User can create DNS records (unauthorized)",           "severity":"Medium", "score":24},
    "constrained_delegation_issues": {"title":"Computers with constrained delegation issues",         "severity":"High",   "score":40},
    "gpo_folder_file_rights_misconf":{"title":"Group policy folder/file rights misconfigured",        "severity":"High",   "score":40},
}

# ---------- helpers ----------
def _resolve_dir(input_dir: str | os.PathLike | None) -> Path:
    if input_dir:
        p = Path(input_dir)
        return p if p.is_dir() else p.parent
    return Path(".").resolve()

def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]
    return data if isinstance(data, list) else []

def _prop(d: Dict[str, Any] | None, key: str, default=None):
    return (d.get("Properties") or {}).get(key, default) if isinstance(d, dict) else default

def _any_text(s) -> str:
    return (s or "").strip()

def _match_any_token(s: str, tokens: List[str]) -> bool:
    ls = s.lower()
    return any(tok in ls for tok in tokens)

def _match_sid_patterns(s: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if re.search(pat, s, flags=re.IGNORECASE):
            return True
    return False

def _principal_is_admin(principal: str) -> bool:
    return _match_any_token(principal, ALLOWED_ADMIN_TOKENS) or _match_sid_patterns(principal, ADMIN_SID_PATTERNS)

def _principal_is_risky(principal: str) -> bool:
    return _match_any_token(principal, RISKY_PRINCIPAL_TOKENS) or _match_sid_patterns(principal, RISKY_SID_PATTERNS)

def _collect_aces(objs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for o in objs:
        for ace in (o.get("Aces") or []):
            out.append(ace)
    return out

def _get_trust_field(trust: Dict[str,Any], key: str):
    for k,v in trust.items():
        if k.lower() == key.lower():
            return v
    return None

# ---------- check functions (pure; fed via closure from run_category13) ----------
def _check_registry_rights_misconfig(gpo_aces, container_aces) -> Tuple[str, List[Dict[str,str]]]:
    hits, seen = [], False
    for ace in (gpo_aces + container_aces):
        rn = _any_text(ace.get("RightName",""))
        pr = _any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
        if "registry" in rn.lower():
            seen = True
            if _principal_is_risky(pr):
                hits.append({"Object":"Registry Right", "Detail": f"{rn} granted to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def _check_container_delegations_insecure(containers) -> Tuple[str, List[Dict[str,str]]]:
    dangerous = {"genericall","genericwrite","writeowner","writedacl","writeproperty","write","modify"}
    hits, seen = [], False
    for cont in containers:
        name = _prop(cont, "name", "<container>")
        for ace in (cont.get("Aces") or []):
            rn = _any_text(ace.get("RightName",""))
            pr = _any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn and rn.lower() in dangerous:
                seen = True
                if not _principal_is_admin(pr):
                    hits.append({"Object": name, "Detail": f"{rn} granted to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def _check_privilege_rights_excessive(domains, groups) -> Tuple[str, List[Dict[str,str]]]:
    hits, seen = [], False
    for obj in (domains + groups):
        objname = _prop(obj, "name", "<object>")
        for ace in (obj.get("Aces") or []):
            rn = _any_text(ace.get("RightName",""))
            pr = _any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn.startswith("Se") and rn.endswith("Privilege"):
                seen = True
                if _principal_is_risky(pr) and not _principal_is_admin(pr):
                    hits.append({"Object": objname, "Detail": f"{rn} assigned to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def _check_auth_policy_silos_misconfig(users) -> Tuple[str, List[Dict[str,str]]]:
    admins = [u for u in users if bool(_prop(u,"admincount", False))]
    if not admins:
        return ("UNKNOWN", [])
    admins_with_silo = [_prop(u,"name","<user>") for u in admins if _any_text(_prop(u,"AuthenticationPolicySilo"))]
    if admins_with_silo:
        return ("PASS", [])
    return ("FAIL", [{"Object":"Users","Detail":"Admin users present but no AuthenticationPolicySilo assigned"}])

def _check_trust_accounts_misused(domains) -> Tuple[str, List[Dict[str,str]]]:
    trusts = []
    for d in domains:
        trusts.extend(d.get("Trusts") or [])
    if not trusts:
        return ("UNKNOWN", [])
    hits = []
    for t in trusts:
        tname = (_get_trust_field(t,"TrustingName") or _get_trust_field(t,"TrustedName") or _prop(t,"name","<trust>"))
        ttype = str(_get_trust_field(t,"TrustType") or "").lower()
        tdir  = str(_get_trust_field(t,"TrustDirection") or "").lower()
        sel   = _get_trust_field(t,"SelectiveAuthentication")
        sidf  = _get_trust_field(t,"SIDFilteringEnabled")

        def to_bool(x):
            if isinstance(x, bool): return x
            s = str(x).strip().lower()
            if s in ("true","1","yes","enabled"): return True
            if s in ("false","0","no","disabled"): return False
            return None

        sel_b, sidf_b = to_bool(sel), to_bool(sidf)
        direction_risky = (tdir in ("two-way","bidirectional","both","inbound"))
        type_risky = True if not ttype else ("external" in ttype or "forest" in ttype or "realm" in ttype or "parent" in ttype)
        if direction_risky and type_risky and ((sel_b is False) or (sidf_b is False)):
            reason = []
            if sel_b is False: reason.append("SelectiveAuthentication=Disabled")
            if sidf_b is False: reason.append("SIDFilteringEnabled=Disabled")
            hits.append({"Object": tname or "<trust>", "Detail": f"Type={ttype or 'unknown'}, Direction={tdir or 'unknown'}; " + ", ".join(reason)})
    return ("FAIL", hits) if hits else ("PASS", [])

def _check_rbac_misconfigured(computers) -> Tuple[str, List[Dict[str,str]]]:
    any_flag, bad = False, []
    for c in computers:
        name = _prop(c,"name","<computer>")
        if "rbac" in (c.get("Properties") or {}):
            any_flag = True
            if not bool(_prop(c,"rbac")):
                bad.append({"Object": name, "Detail":"RBAC=False"})
    if not any_flag:
        return ("UNKNOWN", [])
    return ("FAIL", bad) if bad else ("PASS", [])

def _check_dns_create_unauthorized(users) -> Tuple[str, List[Dict[str,str]]]:
    seen_any_aces, bad = False, []
    for u in users:
        uname = _prop(u,"name","<user>")
        for ace in (u.get("Aces") or []):
            seen_any_aces = True
            rn = _any_text(ace.get("RightName",""))
            if "create dns record" in rn.lower():
                bad.append({"Object": uname, "Detail": f"{rn}"})
                break
    if not seen_any_aces:
        return ("UNKNOWN", [])
    return ("FAIL", bad) if bad else ("PASS", [])

def _check_constrained_delegation_issues(computers) -> Tuple[str, List[Dict[str,str]]]:
    saw_attr, hits = False, []
    for c in computers:
        name = _prop(c,"name","<computer>")
        props = c.get("Properties") or {}
        atd = props.get("msds-allowedtodelegateto") or props.get("msDS-AllowedToDelegateTo")
        t2a = props.get("trustedtoauthfordelegation") or props.get("TrustedToAuthForDelegation")
        cdel= props.get("constraineddelegation") or props.get("ConstrainedDelegation")
        if atd is not None or t2a is not None or cdel is not None:
            saw_attr = True
        details = []
        if atd: details.append(f"AllowedToDelegateTo count={len(atd) if isinstance(atd,list) else 1}")
        if t2a: details.append("TrustedToAuthForDelegation=True")
        if cdel: details.append("ConstrainedDelegation=True")
        if details:
            hits.append({"Object": name, "Detail": ", ".join(details)})
    if not saw_attr:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def _check_gpo_folder_file_rights_misconf(gpos) -> Tuple[str, List[Dict[str,str]]]:
    suspicious = {"genericall","genericwrite","writedacl","writeowner","write","modify","writeproperty","addmember"}
    hits = []
    any_aces = any(g.get("Aces") for g in gpos)
    if not any_aces:
        return ("UNKNOWN", [])
    for g in gpos:
        gname = _prop(g,"name","<GPO>")
        for ace in (g.get("Aces") or []):
            rn = _any_text(ace.get("RightName",""))
            pr = _any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn and rn.lower() in suspicious and not _principal_is_admin(pr):
                hits.append({"Object": gname, "Detail": f"{rn} granted to {pr}"})
    return ("FAIL", hits) if hits else ("PASS", [])

# ---------- public API ----------
def run_category13(input_dir: str | os.PathLike | None) -> Tuple[str, Dict[str, Any]]:
    base = _resolve_dir(input_dir)

    containers = _load_json_list(base / CONTAINERS_FILE)
    users      = _load_json_list(base / USERS_FILE)
    groups     = _load_json_list(base / GROUPS_FILE)
    computers  = _load_json_list(base / COMPUTERS_FILE)
    gpos       = _load_json_list(base / GPOS_FILE)
    domains    = _load_json_list(base / DOMAINS_FILE)

    gpo_aces       = _collect_aces(gpos)
    container_aces = _collect_aces(containers)

    CHECKS = [
        ("registry_rights_misconfig",     lambda: _check_registry_rights_misconfig(gpo_aces, container_aces)),
        ("container_delegations_insecure",lambda: _check_container_delegations_insecure(containers)),
        ("privilege_rights_excessive",    lambda: _check_privilege_rights_excessive(domains, groups)),
        ("auth_policy_silos_misconfig",   lambda: _check_auth_policy_silos_misconfig(users)),
        ("trust_accounts_misused",        lambda: _check_trust_accounts_misused(domains)),
        ("rbac_misconfigured",            lambda: _check_rbac_misconfigured(computers)),
        ("dns_create_unauthorized",       lambda: _check_dns_create_unauthorized(users)),
        ("constrained_delegation_issues", lambda: _check_constrained_delegation_issues(computers)),
        ("gpo_folder_file_rights_misconf",lambda: _check_gpo_folder_file_rights_misconf(gpos)),
    ]

    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}
    unknown_items: List[Dict[str, Any]] = []

    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,  # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if status == "UNKNOWN":
            unknown_items.append(rec)

    total         = len(results)
    failed_total  = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)
    category_risk_total = sum(r["score"] for r in results if r["status"] in ("FAIL","UNKNOWN"))

    risk_by_severity = {"High":0, "Medium":0, "Low":0}
    for r in results:
        if r["status"] in ("FAIL","UNKNOWN"):
            risk_by_severity[r["severity"]] += r["score"]

    # Build report text
    lines: List[str] = []
    lines.append("=== Category 13: Privilege & Trust Management (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 13 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    for sev in ["High","Medium","Low"]:
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

    if unknown_items:
        lines.append("Non-passing (UNKNOWN) checks (counted as FAIL):")
        for r in unknown_items:
            lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "TotalFails": failed_total,
        "Unknown": unknown_total,
        "RiskScore": category_risk_total,
    }
    return report_text, summary

# Optional: quick CLI test (uses current working directory)
if __name__ == "__main__":
    txt, summ = run_category13(None)
    print(txt)
    print("\nSummary:", summ)
