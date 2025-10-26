#!/usr/bin/env python3
import json
import os
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone, timedelta
import re

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"  # AD JSONs folder
USERS_FILE = "nexora.local_users.json"

# Absolute paths to the policy exports you created
POLICY_JSON = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPasswordPolicy.json"
DEFAULT_DOMAIN_POLICY_XML = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPolicy.xml"
ALL_GPOS_XML = r"C:\Users\LENOVO\OneDrive\Desktop\AllGPOs.xml"

# Thresholds (tune as needed)
THRESHOLDS = {
    "min_password_length": 12,        # Low #1
    "lockout_threshold": 5,           # Low #2
    "lockout_duration_minutes": 30,   # Low #3
    "observation_window_minutes": 30, # Low #4
    "min_password_age_days": 1,       # Low #5
    "password_history_count": 24,     # Low #6
}

# Timeroasting heuristic threshold (days)
TIMEROAST_AGE_DAYS = 180

# How many failing objects to print per check (0 = unlimited)
PRINT_MAX_DETAILS = 0

# Scores (weights) and severity labels (fixed per your brief)
CHECK_META = {
    # High
    "blank_passwords":                   {"title": "Accounts with blank passwords",              "severity": "High",   "score": 75},
    "password_not_required":             {"title": "Accounts with password not required",        "severity": "High",   "score": 75},
    "timeroasting":                      {"title": "Accounts vulnerable to timeroasting attack", "severity": "High",   "score": 60},
    # Medium
    "complexity_not_enforced":           {"title": "Password complexity not enforced",           "severity": "Medium", "score": 48},
    "reversible_encryption_enabled":     {"title": "Password reversible encryption enabled",     "severity": "Medium", "score": 48},
    "accounts_rev_pw":                   {"title": "Accounts with reversible passwords",         "severity": "Medium", "score": 48},
    "attr_userPassword":                 {"title": "Accounts with userPassword attribute",       "severity": "Medium", "score": 48},
    "attr_unixUserPassword":             {"title": "Accounts with unixUserPassword attribute",   "severity": "Medium", "score": 48},
    "attr_unicodePwd":                   {"title": "Accounts with unicodePwd attribute",         "severity": "Medium", "score": 48},
    "never_expiring_passwords":          {"title": "Accounts with never-expiring passwords",     "severity": "Medium", "score": 48},
    # Low
    "min_length_lt_X":                   {"title": f"Password length < {THRESHOLDS['min_password_length']}",             "severity": "Low", "score": 36},
    "lockout_threshold_lt_X":            {"title": f"Password threshold < {THRESHOLDS['lockout_threshold']}",            "severity": "Low", "score": 27},
    "lockout_duration_lt_X":             {"title": f"Password lockout duration < {THRESHOLDS['lockout_duration_minutes']} min", "severity": "Low", "score": 27},
    "observation_window_lt_X":           {"title": f"Password lockout observation window < {THRESHOLDS['observation_window_minutes']} min", "severity": "Low", "score": 18},
    "min_age_lt_X":                      {"title": f"Password minimum age < {THRESHOLDS['min_password_age_days']}",     "severity": "Low", "score": 12},
    "history_count_lt_X":                {"title": f"Password history count < {THRESHOLDS['password_history_count']}",   "severity": "Low", "score": 18},
    "attr_altSecurityIdentities":        {"title": "Accounts with altSecurityIdentities",        "severity": "Low",    "score": 27},
    "attr_msDS_HostServiceAccount":      {"title": "Accounts with msDS-HostServiceAccount",      "severity": "Low",    "score": 27},
}

# ========= helpers =========
def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    if isinstance(data, list):
        return data
    return []

def prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

def any_key(d: Dict[str, Any], *keys) -> Tuple[str, Any]:
    P = d.get("Properties") or {}
    for k in keys:
        if k in P:
            return k, P[k]
    return "", None

# --- Policy loaders (JSON preferred, XML fallback) ---
def load_policy_json(path: str):
    if not os.path.exists(path):
        return None
    last_err = None
    for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            with open(path, "r", encoding=enc) as f:
                txt = f.read()
            txt = txt.strip("\ufeff\u200b\u200c\u200d")
            return json.loads(txt)
        except Exception as e:
            last_err = e
            continue
    print(f"[DEBUG] Failed to parse policy JSON: {last_err}")
    return None

def parse_gpo_xml_numbers(xml_path: str) -> dict:
    vals = {}
    if not os.path.exists(xml_path):
        return vals
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {
            "gp": "http://www.microsoft.com/GroupPolicy/Settings",
            "sec": "http://www.microsoft.com/GroupPolicy/Settings/Security",
        }
        for acct in root.findall(".//sec:SecuritySettings/sec:Account", ns):
            name = (acct.findtext("sec:Name", default="", namespaces=ns) or "").lower()
            num = acct.findtext("sec:SettingNumber", default="", namespaces=ns)
            boo = acct.findtext("sec:SettingBoolean", default="", namespaces=ns)
            if name == "minimumpasswordlength" and num.isdigit():
                vals["minpasswordlength"] = int(num)
            elif name == "passwordhistorysize" and num.isdigit():
                vals["passwordhistorysize"] = int(num)
            elif name == "minimumpasswordage" and num.isdigit():
                vals["minpasswordage"] = int(num)
            elif name == "lockoutbadcount" and num.isdigit():
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

# Load policy sources
policy_json = load_policy_json(POLICY_JSON)
ddp_xml_vals = parse_gpo_xml_numbers(DEFAULT_DOMAIN_POLICY_XML)
all_gpos_xml_vals = parse_gpo_xml_numbers(ALL_GPOS_XML)

def get_policy_value(key: str):
    """
    Priority:
      1) DefaultDomainPasswordPolicy.json (exact fields)
      2) DefaultDomainPolicy.xml (parsed)
      3) AllGPOs.xml (parsed)
    """
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

# ========= load AD JSON data =========
users_path = os.path.join(INPUT_DIR, USERS_FILE)
users = load_json(users_path)

# ========= time conversion helpers (for timeroasting) =========
def parse_pwdlastset(value) -> datetime | None:
    if value in (None, 0, "0"):
        return None
    try:
        iv = int(value)
        if iv > 10**14:  # FILETIME
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return epoch + timedelta(microseconds=iv / 10)
        elif iv > 10**9:
            if iv > 10**12:
                return datetime.fromtimestamp(iv / 1000.0, tz=timezone.utc)
            else:
                return datetime.fromtimestamp(iv, tz=timezone.utc)
        else:
            return None
    except Exception:
        pass
    if isinstance(value, str):
        s = value.strip()
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            pass
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            try:
                y, mo, d = map(int, m.groups())
                return datetime(y, mo, d, tzinfo=timezone.utc)
            except Exception:
                pass
    return None

# ========= checks =========
def check_blank_passwords() -> Tuple[str, List[Dict[str, str]]]:
    bad = []
    for u in users:
        pnr = bool(prop(u, "passwordnotreqd", False))
        pls = prop(u, "pwdlastset")
        if pnr and (pls in (None, 0)):
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": f"passwordNotReqd=True & pwdLastSet={pls}"})
    return ("FAIL" if bad else "PASS", bad)

def check_password_not_required() -> Tuple[str, List[Dict[str, str]]]:
    bad = []
    for u in users:
        if bool(prop(u, "passwordnotreqd", False)):
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": "passwordNotReqd=True"})
    return ("FAIL" if bad else "PASS", bad)

def check_timeroasting() -> Tuple[str, List[Dict[str, str]]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=TIMEROAST_AGE_DAYS)
    bad = []
    seen_any = False
    for u in users:
        spns = prop(u, "serviceprincipalnames") or []
        if not spns:
            continue
        pls_raw = prop(u, "pwdlastset")
        pls_dt = parse_pwdlastset(pls_raw)
        if pls_dt is not None:
            seen_any = True
            if pls_dt < cutoff:
                bad.append({
                    "Object": prop(u, "name", "<user>"),
                    "Detail": f"{len(spns)} SPN(s), pwdLastSet={pls_dt.date()} (> {TIMEROAST_AGE_DAYS} days)"
                })
    if not seen_any:
        return ("UNKNOWN", [])
    return ("FAIL" if bad else "PASS", bad)

# Policy checks using get_policy_value()
def check_complexity_not_enforced() -> Tuple[str, List[Dict[str, str]]]:
    v = get_policy_value("passwordcomplexity")
    if v is None:
        return ("UNKNOWN", [])
    return ("PASS" if bool(v) else "FAIL",
            [] if v else [{"Object":"Default Domain Policy","Detail":"Complexity is disabled"}])

def check_reversible_encryption_enabled() -> Tuple[str, List[Dict[str, str]]]:
    v = get_policy_value("reversiblepasswordencryptionenabled")
    if v is None:
        return ("UNKNOWN", [])
    return ("FAIL" if bool(v) else "PASS",
            [{"Object":"Default Domain Policy","Detail":"Reversible encryption ENABLED"}] if v else [])

def numeric_policy_below(key: str, threshold: int, label: str) -> Tuple[str, List[Dict[str, str]]]:
    v = get_policy_value(key)
    if v is None:
        return ("UNKNOWN", [])
    try:
        iv = int(v)
    except Exception:
        return ("UNKNOWN", [])
    if iv < threshold:
        return ("FAIL", [{"Object":"Default Domain Policy", "Detail": f"{label}: {iv} < {threshold}"}])
    return ("PASS", [])

def check_min_length():
    return numeric_policy_below("minpasswordlength", THRESHOLDS["min_password_length"], "Minimum password length")

def check_lockout_threshold():
    return numeric_policy_below("lockoutthreshold", THRESHOLDS["lockout_threshold"], "Lockout threshold")

def check_lockout_duration():
    return numeric_policy_below("lockoutduration", THRESHOLDS["lockout_duration_minutes"], "Lockout duration (minutes)")

def check_observation_window():
    return numeric_policy_below("lockoutobservationwindow", THRESHOLDS["observation_window_minutes"], "Lockout observation window (minutes)")

def check_min_age():
    v = get_policy_value("minpasswordage")
    if v is None:
        return ("UNKNOWN", [])
    try:
        iv = int(v)
    except Exception:
        return ("UNKNOWN", [])
    if iv < THRESHOLDS["min_password_age_days"]:
        return ("FAIL", [{"Object":"Default Domain Policy", "Detail": f"Minimum password age: {iv} < {THRESHOLDS['min_password_age_days']}"}])
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
        return ("FAIL", [{"Object":"Default Domain Policy", "Detail": f"Password history size: {iv} < {THRESHOLDS['password_history_count']}"}])
    return ("PASS", [])

# Attribute presence checks (users)
def check_accounts_rev_pw() -> Tuple[str, List[Dict[str, str]]]:
    bad = []
    for u in users:
        _, val = any_key(u, "reversiblepasswordenabled")
        if val is True:
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": "reversiblePasswordEnabled=True"})
    return ("FAIL" if bad else "PASS", bad)

def check_attr_presence(attr_variants: List[str], label: str) -> Tuple[str, List[Dict[str, str]]]:
    bad = []
    for u in users:
        present = any(a in (u.get("Properties") or {}) for a in attr_variants)
        if present:
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": f"{label} present"})
    return ("FAIL" if bad else "PASS", bad)

def check_never_expiring_passwords() -> Tuple[str, List[Dict[str, str]]]:
    """New Medium check (score 48): Accounts with pwdNeverExpires=True."""
    bad = []
    for u in users:
        if bool(prop(u, "pwdneverexpires", False)):
            bad.append({"Object": prop(u, "name", "<user>"), "Detail": "pwdNeverExpires=True"})
    return ("FAIL" if bad else "PASS", bad)

# ========= run all checks (now 20 with never-expiring) =========
checks_run_order = [
    # High
    ("blank_passwords",               check_blank_passwords),
    ("password_not_required",         check_password_not_required),
    ("timeroasting",                  check_timeroasting),
    # Medium
    ("complexity_not_enforced",       check_complexity_not_enforced),
    ("reversible_encryption_enabled", check_reversible_encryption_enabled),
    ("accounts_rev_pw",               check_accounts_rev_pw),
    ("attr_userPassword",             lambda: check_attr_presence(["userpassword"], "userPassword")),
    ("attr_unixUserPassword",         lambda: check_attr_presence(["unixuserpassword","unixpassword","sfupassword"], "unixUserPassword")),
    ("attr_unicodePwd",               lambda: check_attr_presence(["unicodepwd","unicodepassword"], "unicodePwd")),
    ("never_expiring_passwords",      check_never_expiring_passwords),   # <— NEW
    # Low (policy)
    ("min_length_lt_X",               check_min_length),
    ("lockout_threshold_lt_X",        check_lockout_threshold),
    ("lockout_duration_lt_X",         check_lockout_duration),
    ("observation_window_lt_X",       check_observation_window),
    ("min_age_lt_X",                  check_min_age),
    ("history_count_lt_X",            check_history_count),
    ("attr_altSecurityIdentities",    lambda: check_attr_presence(["altsecurityidentities"], "altSecurityIdentities")),
    ("attr_msDS_HostServiceAccount",  lambda: check_attr_presence(["msds-hostserviceaccount","msdshostserviceaccount"], "msDS-HostServiceAccount")),
]

# ========= execute & print =========
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

by_sev_counts = Counter()
for r in results:
    if r["status"] == "FAIL":
        by_sev_counts[r["severity"]] += 1

# Compute risk score totals (score counted once per failed check)
category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
risk_by_severity = defaultdict(int)
for r in results:
    if r["status"] == "FAIL":
        risk_by_severity[r["severity"]] += r["score"]

print("\n=== Category 1: Password & Account Policy Checks (Runtime Report) ===")
print(f"Checks evaluated: {total}")
print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
print(f"Category 1 Total Risk Score: {category_risk_total}")
print(f"  - High risk points:   {risk_by_severity['High']}")
print(f"  - Medium risk points: {risk_by_severity['Medium']}")
print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

print("Failures by severity:")
print(f"  High  : {by_sev_counts.get('High', 0)}")
print(f"  Medium: {by_sev_counts.get('Medium', 0)}")
print(f"  Low   : {by_sev_counts.get('Low', 0)}\n")

def print_failed_block(sev: str):
    items = failed_by_sev.get(sev, [])
    if not items:
        print(f"{sev}: (none)")
        return
    print(f"{sev}:")
    for r in items:
        print(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} object(s)")
        details = r["details"]
        limit = PRINT_MAX_DETAILS
        if limit and len(details) > limit:
            for d in details[:limit]:
                print(f"      • {d.get('Object')} - {d.get('Detail')}")
            print(f"      ... and {len(details)-limit} more")
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

# Combined view of sensitive attributes per user
def summarize_sensitive_attrs():
    attrs = ["userpassword","unixuserpassword","unixpassword","sfupassword","unicodepwd","unicodepassword"]
    per_user = {}
    for u in users:
        name = prop(u, "name", "<user>")
        present = [a for a in attrs if a in (u.get("Properties") or {})]
        if present:
            per_user[name] = present
    if not per_user:
        print("\nNo users with sensitive password attributes.")
        return
    print("\nUsers with sensitive password attributes (combined):")
    for name in sorted(per_user.keys(), key=lambda s: s.lower()):
        nice = []
        for a in per_user[name]:
            a2 = (a.replace("unicodepwd","unicodePwd")
                    .replace("userpassword","userPassword")
                    .replace("unixuserpassword","unixUserPassword")
                    .replace("sfupassword","sfuPassword")
                    .replace("unicodepassword","unicodePassword")
                    .replace("unixpassword","unixPassword"))
            nice.append(a2)
        print(f"  • {name} -> {', '.join(nice)}")

summarize_sensitive_attrs()
print()

def run_category1(input_dir: str):
    """
    Wrapper for Category 1: runs the checks, captures the full console-style
    report, and returns both the report text and summary dict.
    """

    # ---------------- Run the existing checks ----------------
    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}

    for key, fn in checks_run_order:
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