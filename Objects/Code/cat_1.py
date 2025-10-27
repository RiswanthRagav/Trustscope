# cat_1.py — Password & Account Policy Checks (safe for Streamlit import)
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timezone, timedelta
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
import re

# ========= THRESHOLDS & SCORING (same as your original) =========
THRESHOLDS = {
    "min_password_length": 12,        # Low #1
    "lockout_threshold": 5,           # Low #2
    "lockout_duration_minutes": 30,   # Low #3
    "observation_window_minutes": 30, # Low #4
    "min_password_age_days": 1,       # Low #5
    "password_history_count": 24,     # Low #6
}

TIMEROAST_AGE_DAYS = 180
PRINT_MAX_DETAILS = 0  # app builds a text report; we won't print() on import

CHECK_META = {
    # High
    "blank_passwords":               {"title": "Accounts with blank passwords",              "severity": "High",   "score": 75},
    "password_not_required":         {"title": "Accounts with password not required",        "severity": "High",   "score": 75},
    "timeroasting":                  {"title": "Accounts vulnerable to timeroasting attack", "severity": "High",   "score": 60},
    # Medium
    "complexity_not_enforced":       {"title": "Password complexity not enforced",           "severity": "Medium", "score": 48},
    "reversible_encryption_enabled": {"title": "Password reversible encryption enabled",     "severity": "Medium", "score": 48},
    "accounts_rev_pw":               {"title": "Accounts with reversible passwords",         "severity": "Medium", "score": 48},
    "attr_userPassword":             {"title": "Accounts with userPassword attribute",       "severity": "Medium", "score": 48},
    "attr_unixUserPassword":         {"title": "Accounts with unixUserPassword attribute",   "severity": "Medium", "score": 48},
    "attr_unicodePwd":               {"title": "Accounts with unicodePwd attribute",         "severity": "Medium", "score": 48},
    "never_expiring_passwords":      {"title": "Accounts with never-expiring passwords",     "severity": "Medium", "score": 48},
    # Low
    "min_length_lt_X":               {"title": f"Password length < {THRESHOLDS['min_password_length']}",             "severity": "Low", "score": 36},
    "lockout_threshold_lt_X":        {"title": f"Password threshold < {THRESHOLDS['lockout_threshold']}",            "severity": "Low", "score": 27},
    "lockout_duration_lt_X":         {"title": f"Password lockout duration < {THRESHOLDS['lockout_duration_minutes']} min", "severity": "Low", "score": 27},
    "observation_window_lt_X":       {"title": f"Password lockout observation window < {THRESHOLDS['observation_window_minutes']} min", "severity": "Low", "score": 18},
    "min_age_lt_X":                  {"title": f"Password minimum age < {THRESHOLDS['min_password_age_days']}",     "severity": "Low", "score": 12},
    "history_count_lt_X":            {"title": f"Password history count < {THRESHOLDS['password_history_count']}",   "severity": "Low", "score": 18},
    "attr_altSecurityIdentities":    {"title": "Accounts with altSecurityIdentities",        "severity": "Low",    "score": 27},
    "attr_msDS_HostServiceAccount":  {"title": "Accounts with msDS-HostServiceAccount",      "severity": "Low",    "score": 27},
}

# ========= small helpers =========
def _load_json_any(path: Path) -> List[Dict[str, Any]] | Dict[str, Any] | List[Any]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return data

def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    obj = _load_json_any(path)
    return obj if isinstance(obj, list) else []

def _prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

def _any_key(d: Dict[str, Any], *keys) -> Tuple[str, Any]:
    P = d.get("Properties") or {}
    for k in keys:
        if k in P:
            return k, P[k]
    return "", None

def _parse_pwdlastset(value) -> Optional[datetime]:
    if value in (None, 0, "0"):
        return None
    try:
        iv = int(value)
        if iv > 10**14:  # FILETIME 100ns since 1601-01-01
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return epoch + timedelta(microseconds=iv / 10)
        elif iv > 10**9:
            if iv > 10**12:  # ms
                return datetime.fromtimestamp(iv / 1000.0, tz=timezone.utc)
            else:            # s
                return datetime.fromtimestamp(iv, tz=timezone.utc)
    except Exception:
        pass
    if isinstance(value, str):
        s = value.strip()
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
            if m:
                y, mo, d = map(int, m.groups())
                return datetime(y, mo, d, tzinfo=timezone.utc)
    return None

# ========= policy loaders (JSON preferred, XML fallback) =========
def _load_policy_json(path: Path):
    if not path.exists():
        return None
    last_err = None
    for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            txt = path.read_text(encoding=enc)
            txt = txt.strip("\ufeff\u200b\u200c\u200d")
            return json.loads(txt)
        except Exception as e:
            last_err = e
            continue
    # If totally unreadable, return None (we won’t raise at import)
    return None

def _parse_gpo_xml_numbers(xml_path: Path) -> dict:
    vals = {}
    if not xml_path.exists():
        return vals
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        ns = {
            "gp": "http://www.microsoft.com/GroupPolicy/Settings",
            "sec": "http://www.microsoft.com/GroupPolicy/Settings/Security",
        }
        for acct in root.findall(".//sec:SecuritySettings/sec:Account", ns):
            name = (acct.findtext("sec:Name", default="", namespaces=ns) or "").lower()
            num = acct.findtext("sec:SettingNumber", default="", namespaces=ns)
            boo = acct.findtext("sec:SettingBoolean", default="", namespaces=ns)
            if name == "minimumpasswordlength" and num and num.isdigit():
                vals["minpasswordlength"] = int(num)
            elif name == "passwordhistorysize" and num and num.isdigit():
                vals["passwordhistorysize"] = int(num)
            elif name == "minimumpasswordage" and num and num.isdigit():
                vals["minpasswordage"] = int(num)
            elif name == "lockoutbadcount" and num and num.isdigit():
                vals["lockoutthreshold"] = int(num)
            elif name == "passwordcomplexity" and boo != "":
                vals["passwordcomplexity"] = (boo.lower() == "true")
        for secopt in root.findall(".//sec:SecuritySettings/sec:Registry", ns):
            name = (secopt.findtext("sec:Name", default="", namespaces=ns) or "").lower()
            boo = secopt.findtext("sec:SettingBoolean", default="", namespaces=ns)
            if "reversible" in name and boo != "":
                vals["reversiblepasswordencryptionenabled"] = (boo.lower() == "true")
        return vals
    except Exception:
        return {}

def _make_get_policy_value(policy_json, ddp_xml_vals: dict, all_gpos_xml_vals: dict):
    """
    Returns a closure get_policy_value(key) with this priority:
      1) DefaultDomainPasswordPolicy.json
      2) DefaultDomainPolicy.xml
      3) AllGPOs.xml
    """
    def get_policy_value(key: str):
        if policy_json:
            mapping = {
                "minpasswordlength": ("MinPasswordLength", None),
                "passwordhistorysize": ("PasswordHistoryCount", None),
                "minpasswordage": ("MinPasswordAge", "Days"),
                "lockoutthreshold": ("LockoutThreshold", None),
                "lockoutduration": ("LockoutDuration", "Minutes"),
                "lockoutobservationwindow": ("LockoutObservationWindow", "Minutes"),
                "passwordcomplexity": ("ComplexityEnabled", None),
                "reversiblepasswordencryptionenabled": ("ReversibleEncryptionEnabled", None),
            }
            if key in mapping:
                parent, sub = mapping[key]
                val = policy_json.get(parent)
                if val is not None:
                    return val.get(sub) if (isinstance(val, dict) and sub) else val
        if key in ddp_xml_vals:
            return ddp_xml_vals[key]
        if key in all_gpos_xml_vals:
            return all_gpos_xml_vals[key]
        return None
    return get_policy_value

# ========= main API =========
def run_category1(input_dir: str | Path, policy_dir: str | Path | None = None) -> Tuple[str, Dict[str, Any]]:
    """
    Execute Category 1 checks. Safe to import in Streamlit.
    - input_dir: folder containing nexora.local_*.json files
    - policy_dir: folder containing policy exports (JSON/XML). If None, we try to auto-detect.
    Returns: (report_text, summary_dict)
    """
    base = Path(input_dir)

    # Load users (no top-level I/O)
    users: List[Dict[str, Any]] = _load_json_list(base / "nexora.local_users.json")

    # Locate policy files in a repo-friendly way (no absolute Windows paths)
    if policy_dir is None:
        # Try some sensible locations relative to input_dir
        candidates = [
            Path(policy_dir) for policy_dir in []  # placeholder to keep typing happy
        ]
        # Common places: alongside data, sibling "Policies" under Objects, or repo root subdir
        candidates.extend([
            base,                               # same folder as AD JSONs
            base.parent / "Domian Data",           # e.g. Objects/Policies
            base.parent,                        # Objects/
            base.parent.parent / "Trustscope",    # repo-root/Policies
        ])
        # Deduplicate while preserving order
        seen = set()
        folders = []
        for p in candidates:
            if p and p not in seen:
                seen.add(p)
                folders.append(p)
    else:
        folders = [Path(policy_dir)]

    policy_json = None
    ddp_xml_vals: dict = {}
    all_gpos_xml_vals: dict = {}

    # Try to discover files with standard names
    for folder in folders:
        if not folder.exists():
            continue
        j = folder / "DefaultDomainPasswordPolicy.json"
        x1 = folder / "DefaultDomainPolicy.xml"
        x2 = folder / "AllGPOs.xml"
        if policy_json is None and j.exists():
            policy_json = _load_policy_json(j)
        if not ddp_xml_vals and x1.exists():
            ddp_xml_vals = _parse_gpo_xml_numbers(x1)
        if not all_gpos_xml_vals and x2.exists():
            all_gpos_xml_vals = _parse_gpo_xml_numbers(x2)
        # If we’ve found at least one, keep going to fill the rest

    get_policy_value = _make_get_policy_value(policy_json, ddp_xml_vals, all_gpos_xml_vals)

    # ---------- checks (rewired to use local datasets) ----------
    def check_blank_passwords():
        bad = []
        for u in users:
            pnr = bool(_prop(u, "passwordnotreqd", False))
            pls = _prop(u, "pwdlastset")
            if pnr and (pls in (None, 0)):
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": f"passwordNotReqd=True & pwdLastSet={pls}"})
        return ("FAIL" if bad else "PASS", bad)

    def check_password_not_required():
        bad = []
        for u in users:
            if bool(_prop(u, "passwordnotreqd", False)):
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": "passwordNotReqd=True"})
        return ("FAIL" if bad else "PASS", bad)

    def check_timeroasting():
        cutoff = datetime.now(timezone.utc) - timedelta(days=TIMEROAST_AGE_DAYS)
        bad = []
        seen_any = False
        for u in users:
            spns = _prop(u, "serviceprincipalnames") or []
            if not spns:
                continue
            pls_raw = _prop(u, "pwdlastset")
            pls_dt = _parse_pwdlastset(pls_raw)
            if pls_dt is not None:
                seen_any = True
                if pls_dt < cutoff:
                    bad.append({
                        "Object": _prop(u, "name", "<user>"),
                        "Detail": f"{len(spns)} SPN(s), pwdLastSet={pls_dt.date()} (> {TIMEROAST_AGE_DAYS} days)"
                    })
        if not seen_any:
            return ("UNKNOWN", [])
        return ("FAIL" if bad else "PASS", bad)

    def check_complexity_not_enforced():
        v = get_policy_value("passwordcomplexity")
        if v is None:
            return ("UNKNOWN", [])
        return ("PASS" if bool(v) else "FAIL",
                [] if v else [{"Object": "Default Domain Policy", "Detail": "Complexity is disabled"}])

    def check_reversible_encryption_enabled():
        v = get_policy_value("reversiblepasswordencryptionenabled")
        if v is None:
            return ("UNKNOWN", [])
        return ("FAIL" if bool(v) else "PASS",
                [{"Object": "Default Domain Policy", "Detail": "Reversible encryption ENABLED"}] if v else [])

    def numeric_policy_below(key: str, threshold: int, label: str):
        v = get_policy_value(key)
        if v is None:
            return ("UNKNOWN", [])
        try:
            iv = int(v)
        except Exception:
            return ("UNKNOWN", [])
        if iv < threshold:
            return ("FAIL", [{"Object": "Default Domain Policy", "Detail": f"{label}: {iv} < {threshold}"}])
        return ("PASS", [])

    def check_min_length():          return numeric_policy_below("minpasswordlength", THRESHOLDS["min_password_length"], "Minimum password length")
    def check_lockout_threshold():   return numeric_policy_below("lockoutthreshold", THRESHOLDS["lockout_threshold"], "Lockout threshold")
    def check_lockout_duration():    return numeric_policy_below("lockoutduration", THRESHOLDS["lockout_duration_minutes"], "Lockout duration (minutes)")
    def check_observation_window():  return numeric_policy_below("lockoutobservationwindow", THRESHOLDS["observation_window_minutes"], "Lockout observation window (minutes)")

    def check_min_age():
        v = get_policy_value("minpasswordage")
        if v is None:
            return ("UNKNOWN", [])
        try:
            iv = int(v)
        except Exception:
            return ("UNKNOWN", [])
        if iv < THRESHOLDS["min_password_age_days"]:
            return ("FAIL", [{"Object": "Default Domain Policy", "Detail": f"Minimum password age: {iv} < {THRESHOLDS['min_password_age_days']}"}])
        return ("PASS", [])

    def check_history_count():
        v = get_policy_value("passwordhistorysize")
        if v is None:
            return ("UNKNOWN", [])
        try:
            iv = int(v)
        except Exception:
            return ("UNKNOWN", [])
        if iv < THRESHOLDS["password_history_count"]:
            return ("FAIL", [{"Object": "Default Domain Policy", "Detail": f"Password history size: {iv} < {THRESHOLDS['password_history_count']}"}])
        return ("PASS", [])

    def check_accounts_rev_pw():
        bad = []
        for u in users:
            _, val = _any_key(u, "reversiblepasswordenabled")
            if val is True:
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": "reversiblePasswordEnabled=True"})
        return ("FAIL" if bad else "PASS", bad)

    def _check_attr_presence(attr_variants: List[str], label: str):
        bad = []
        for u in users:
            present = any(a in (u.get("Properties") or {}) for a in attr_variants)
            if present:
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": f"{label} present"})
        return ("FAIL" if bad else "PASS", bad)

    def check_never_expiring_passwords():
        bad = []
        for u in users:
            if bool(_prop(u, "pwdneverexpires", False)):
                bad.append({"Object": _prop(u, "name", "<user>"), "Detail": "pwdNeverExpires=True"})
        return ("FAIL" if bad else "PASS", bad)

    checks_run_order = [
        # High
        ("blank_passwords",               check_blank_passwords),
        ("password_not_required",         check_password_not_required),
        ("timeroasting",                  check_timeroasting),
        # Medium
        ("complexity_not_enforced",       check_complexity_not_enforced),
        ("reversible_encryption_enabled", check_reversible_encryption_enabled),
        ("accounts_rev_pw",               check_accounts_rev_pw),
        ("attr_userPassword",             lambda: _check_attr_presence(["userpassword"], "userPassword")),
        ("attr_unixUserPassword",         lambda: _check_attr_presence(["unixuserpassword","unixpassword","sfupassword"], "unixUserPassword")),
        ("attr_unicodePwd",               lambda: _check_attr_presence(["unicodepwd","unicodepassword"], "unicodePwd")),
        ("never_expiring_passwords",      check_never_expiring_passwords),
        # Low
        ("min_length_lt_X",               check_min_length),
        ("lockout_threshold_lt_X",        check_lockout_threshold),
        ("lockout_duration_lt_X",         check_lockout_duration),
        ("observation_window_lt_X",       check_observation_window),
        ("min_age_lt_X",                  check_min_age),
        ("history_count_lt_X",            check_history_count),
        ("attr_altSecurityIdentities",    lambda: _check_attr_presence(["altsecurityidentities"], "altSecurityIdentities")),
        ("attr_msDS_HostServiceAccount",  lambda: _check_attr_presence(["msds-hostserviceaccount","msdshostserviceaccount"], "msDS-HostServiceAccount")),
    ]

    # ---------- execute checks (no prints; we build a text blob) ----------
    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}

    for key, fn in checks_run_order:
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

    # ---------- build text report (returned to the app) ----------
    lines: List[str] = []
    lines.append("=== Category 1: Password & Account Policy Checks (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 1 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    def add_block(sev: str):
        items = failed_by_sev.get(sev, [])
        if not items:
            lines.append(f"{sev}: (none)")
            return
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} object(s)")
            details = r["details"]
            limit = PRINT_MAX_DETAILS
            if limit and len(details) > limit:
                for d in details[:limit]:
                    lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
                lines.append(f"      ... and {len(details)-limit} more")
            else:
                for d in details:
                    lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    add_block("High")
    add_block("Medium")
    add_block("Low")

    report_text = "\n".join(lines)

    summary = {
        "Category": "Password & Account Policy Checks",
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "Unknown": unknown_total,
        "TotalFails": failed_total,
        "RiskScore": category_risk_total,
        # "MaxScore": optional if you want weighted %
    }

    return report_text, summary
