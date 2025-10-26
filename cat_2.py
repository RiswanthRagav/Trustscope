#!/usr/bin/env python3
import json, os, xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone, timedelta

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"  # <-- change if needed

# Core BloodHound-like dumps (optional fallback sources)
USERS_FILE     = "nexora.local_users.json"
DOMAINS_FILE   = "nexora.local_domains.json"
COMPUTERS_FILE = "nexora.local_computers.json"
GPO_FILE       = "nexora.local_gpos.json"

# Extra exports you created for Category 2 (preferred if present)
DC_ENC_JSON        = r"C:\Users\LENOVO\OneDrive\Desktop\DC_SupportedEncryptionTypes.json"
DOMAIN_ENC_JSON    = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_EncrytptionTypes.json"   # (intentional filename from your upload)
DOMAIN_MODE_JSON   = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_FunctionalLevel.json"
DOMAIN_PAM_JSON    = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_PAM.json"
POLICY_JSON        = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPasswordPolicy.json"
DDP_XML            = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPolicy.xml"
ALL_GPOS_XML       = r"C:\Users\LENOVO\OneDrive\Desktop\AllGPOs.xml"
# Extra exports you created for Category 2 (preferred if present)
DC_ENC_JSON        = r"C:\Users\LENOVO\OneDrive\Desktop\DC_SupportedEncryptionTypes.json"
DOMAIN_ENC_JSON    = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_EncrytptionTypes.json"
DOMAIN_MODE_JSON   = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_FunctionalLevel.json"
DOMAIN_PAM_JSON    = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_PAM.json"
DOMAIN_RECYCLEBIN_JSON = r"C:\Users\LENOVO\OneDrive\Desktop\Domain_RecycleBin.json"   # <-- ADD THIS
POLICY_JSON        = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPasswordPolicy.json"
DDP_XML            = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPolicy.xml"
ALL_GPOS_XML       = r"C:\Users\LENOVO\OneDrive\Desktop\AllGPOs.xml"


# Tunables
MIN_FUNCTIONAL_LEVEL = 2016         # treat below this as too low
KRBTGT_MAX_AGE_DAYS  = 40           # “Kerberos password last changed > 40 days”
PRINT_MAX_DETAILS    = 10           # 0 = unlimited details per check

# ====== Risk model (scores) ======
CHECK_META = {
    # High
    "weak_encryption_dcs":       {"title": "Weak encryption by Domain Controllers",                "severity": "High",   "score": 40},
    # Medium
    "laps_not_installed":        {"title": "LAPS not installed",                                   "severity": "Medium", "score": 32},
    "weak_kerberos_algos":       {"title": "Weak Kerberos encryption algorithms",                  "severity": "Medium", "score": 32},
    "bitlocker_key_not_in_ad":   {"title": "BitLocker recovery key not stored in AD",              "severity": "Medium", "score": 24},
    "krbtgt_pwd_old":            {"title": f"Kerberos password last changed > {KRBTGT_MAX_AGE_DAYS} days", "severity": "Medium", "score": 24},
    "functional_level_low":      {"title": "Functional level too low",                             "severity": "Medium", "score": 18},
    "pso_misconfig":             {"title": "Password Settings Object misconfiguration",            "severity": "Medium", "score": 18},
    "pam_not_enabled":           {"title": "Privileged Access Management not enabled",             "severity": "Medium", "score": 18},
    # Low
    "recycle_bin_not_enabled":   {"title": "Recycle Bin feature not enabled",                      "severity": "Low",    "score": 8},
}

# ========= helpers =========
def pjoin(*a): return os.path.join(*a)

def load_json_list(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path): return []
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    if isinstance(data, list): return data
    return []

def load_json_obj(path: str):
    if not os.path.exists(path): return None
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)

def prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

def filetime_to_datetime(v) -> datetime | None:
    if v in (None, 0, "0"): return None
    try:
        iv = int(v)
        if iv > 10**14:  # FILETIME -> microseconds since 1601-01-01
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return epoch + timedelta(microseconds=iv / 10)
        elif iv > 10**12:  # ms epoch
            return datetime.fromtimestamp(iv/1000.0, tz=timezone.utc)
        elif iv > 10**9:   # s epoch
            return datetime.fromtimestamp(iv, tz=timezone.utc)
    except Exception:
        pass
    # ISO-ish fallback
    if isinstance(v, str):
        try: return datetime.fromisoformat(v.replace("Z","+00:00"))
        except Exception: return None
    return None

def parse_gpo_xml_for_bits(xml_path: str) -> Dict[str, Any]:
    """Parse Get-GPOReport XML for:
       - Kerberos SupportedEncryptionTypes (registry-based policy)
       - BitLocker 'Store recovery info in AD DS' flag
    """
    out = {"kerberos_supported_encryption_types": [], "bitlocker_store_recovery_in_ad_enabled": None}
    if not os.path.exists(xml_path): return out
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {"gp":"http://www.microsoft.com/GroupPolicy/Settings",
              "sec":"http://www.microsoft.com/GroupPolicy/Settings/Security"}
        # Registry-based security options
        for reg in root.findall(".//sec:SecuritySettings/sec:Registry", ns):
            name   = (reg.findtext("sec:Name",    default="", namespaces=ns) or "")
            num    =  reg.findtext("sec:SettingNumber",       default="", namespaces=ns)
            bval   =  reg.findtext("sec:SettingBoolean",      default="", namespaces=ns)
            disp   = (reg.findtext("sec:Display", default="", namespaces=ns) or "")
            lname, ldisp = name.lower(), disp.lower()

            # Kerberos SupportedEncryptionTypes policy
            if "supportedencryptiontypes" in lname or "supported encryption types" in ldisp:
                if num and num.isdigit():
                    out["kerberos_supported_encryption_types"].append(int(num))

            # BitLocker store recovery info in AD DS (OS/Fixed/Removable variants)
            if ("bitlocker" in lname or "bitlocker" in ldisp) and ("store" in lname or "store" in ldisp):
                if bval:  # true/false
                    val = (bval.lower() == "true")
                    # if any drive type enabled, treat as enabled
                    out["bitlocker_store_recovery_in_ad_enabled"] = True if val else (out["bitlocker_store_recovery_in_ad_enabled"] or False)
        return out
    except Exception:
        return out

# ========= load data =========
users      = load_json_list(pjoin(INPUT_DIR, USERS_FILE))
domains    = load_json_list(pjoin(INPUT_DIR, DOMAINS_FILE))
computers  = load_json_list(pjoin(INPUT_DIR, COMPUTERS_FILE))
gpos       = load_json_list(pjoin(INPUT_DIR, GPO_FILE))

dc_enc_obj    = load_json_obj(pjoin(INPUT_DIR, DC_ENC_JSON))          # list or single
domain_enc    = load_json_obj(pjoin(INPUT_DIR, DOMAIN_ENC_JSON))      # single object expected
domain_mode   = load_json_obj(pjoin(INPUT_DIR, DOMAIN_MODE_JSON))     # single object expected
domain_pam    = load_json_obj(pjoin(INPUT_DIR, DOMAIN_PAM_JSON))      # single object expected
policy_json   = load_json_obj(pjoin(INPUT_DIR, POLICY_JSON))          # not strictly required here
gpo_xml_1     = parse_gpo_xml_for_bits(pjoin(INPUT_DIR, DDP_XML))
gpo_xml_2     = parse_gpo_xml_for_bits(pjoin(INPUT_DIR, ALL_GPOS_XML))

# Merge XML signals
KERB_SUPPORTED_TYPES_XML = (gpo_xml_1["kerberos_supported_encryption_types"] +
                            gpo_xml_2["kerberos_supported_encryption_types"])
BITLOCKER_STORE_AD = (gpo_xml_1["bitlocker_store_recovery_in_ad_enabled"]
                      if gpo_xml_1["bitlocker_store_recovery_in_ad_enabled"] is not None
                      else gpo_xml_2["bitlocker_store_recovery_in_ad_enabled"])

# ========= normalizers for new JSONs =========
def get_dc_supported_enc_values() -> List[int]:
    vals: List[int] = []
    if isinstance(dc_enc_obj, dict) and "SupportedEncryptionTypes" in dc_enc_obj:
        vals.append(dc_enc_obj["SupportedEncryptionTypes"])
    elif isinstance(dc_enc_obj, list):
        for it in dc_enc_obj:
            v = it.get("SupportedEncryptionTypes")
            if isinstance(v, (int, float)): vals.append(int(v))
    # Fallback from computers dump if present
    if not vals and computers:
        for c in computers:
            v = prop(c, "supportedencryptiontypes")
            if isinstance(v, (int, float)): vals.append(int(v))
    return vals

def get_domain_supported_enc_value() -> int | None:
    if isinstance(domain_enc, dict):
        v = domain_enc.get("msDS-SupportedEncryptionTypes")
        if isinstance(v, (int, float)): return int(v)
    return None

def get_domain_mode_value() -> int | None:
    # Prefer Domain_FunctionalLevel.json if present
    if isinstance(domain_mode, dict):
        v = domain_mode.get("DomainMode")
        if isinstance(v, (int, float)): return int(v)
        # sometimes DomainMode is stringified number
        try:
            return int(str(v))
        except Exception:
            pass
    # Fallback to domains.json if populated
    best = None
    for d in domains:
        fl = prop(d, "functionallevel")
        if isinstance(fl, (int, float)): best = max(best or 0, int(fl))
        elif isinstance(fl, str) and fl.isdigit(): best = max(best or 0, int(fl))
    return best

def get_pam_enabled() -> bool | None:
    if isinstance(domain_pam, dict):
        v = domain_pam.get("PrivilegedAccessManagementEnabled")
        if v in ([], None): return False
        return bool(v)
    # Fallback to domains.json boolean if present
    for d in domains:
        v = prop(d, "privilegedaccessmanagementenabled")
        if v is not None: return bool(v)
    return None

def get_recycle_bin_enabled() -> bool | None:
    # Prefer domains.json (some dumps include it)
    for d in domains:
        v = prop(d, "recyclebinenabled")
        if v is not None: return bool(v)
    # If Domain_Core.json existed we’d read it here; otherwise unknown
    return None

def any_computer_has_laps_signals() -> bool:
    # Legacy LAPS
    for c in computers:
        P = c.get("Properties") or {}
        if "admpwd" in P or "admpwdexpirationtime" in P:
            return True
        # Windows LAPS (names vary in exports; try a loose check)
        lname_keys = [k.lower() for k in P.keys()]
        if any(k.startswith("mslaps") or "mslaps-" in k for k in lname_keys):
            return True
    # GPO hint
    if any("laps" in (prop(g, "name","") or "").lower() for g in gpos):
        return True
    return False

def krbtgt_password_age_over(days: int) -> Tuple[bool, List[Dict[str,str]] | None]:
    if not users: return (False, None)
    now = datetime.now(timezone.utc)
    hits = []
    saw = False
    for u in users:
        sam = (prop(u, "samaccountname","") or "").lower()
        if sam == "krbtgt":
            saw = True
            dt = filetime_to_datetime(prop(u, "pwdlastset"))
            if dt is None: continue
            age = (now - dt).days
            if age > days:
                hits.append({"Object": prop(u,"name","krbtgt"),
                             "Detail": f"pwdLastSet={dt.date()} ({age} days old)"})
    if not saw: return (False, None)  # unknown
    return (len(hits) > 0, hits)

# ========= checks =========
def check_weak_encryption_dcs():
    vals = get_dc_supported_enc_values()
    if not vals: return ("UNKNOWN", [])
    bad = []
    for v in vals:
        # weak bits: DES (0x1/0x2), RC4 (0x4)
        if (v & 0x1) or (v & 0x2) or (v & 0x4):
            bad.append({"Object": "DomainController", "Detail": f"SupportedEncryptionTypes includes DES/RC4 (value {v})"})
    return ("FAIL", bad) if bad else ("PASS", [])

def check_weak_kerberos_algos():
    # Prefer domain-level policy value
    d = get_domain_supported_enc_value()
    if d is not None:
        weak = (d & 0x1) or (d & 0x2) or (d & 0x4)
        return ("FAIL", [{"Object":"Domain","Detail":f"Domain SupportedEncryptionTypes {d} includes DES/RC4"}]) if weak else ("PASS", [])
    # Next use GPO XML policy
    if KERB_SUPPORTED_TYPES_XML:
        weak_any = any((v & 0x1) or (v & 0x2) or (v & 0x4) for v in KERB_SUPPORTED_TYPES_XML)
        return ("FAIL", [{"Object":"GPO Policy","Detail":f"SupportedEncryptionTypes in GPO includes DES/RC4: {KERB_SUPPORTED_TYPES_XML}"}]) if weak_any else ("PASS", [])
    # Fallback: infer from DC values
    vals = get_dc_supported_enc_values()
    if vals:
        weak_any = any((v & 0x1) or (v & 0x2) or (v & 0x4) for v in vals)
        return ("FAIL", [{"Object":"Inferred from DCs","Detail":f"DC values include DES/RC4: {vals}"}]) if weak_any else ("PASS", [])
    return ("UNKNOWN", [])

def check_functional_level_low():
    dm = get_domain_mode_value()
    if dm is None: return ("UNKNOWN", [])
    return ("PASS", []) if int(dm) >= int(MIN_FUNCTIONAL_LEVEL) else ("FAIL", [{"Object":"Domain","Detail":f"DomainMode={dm} < {MIN_FUNCTIONAL_LEVEL}"}])

def check_pam_not_enabled():
    v = get_pam_enabled()
    if v is None: return ("UNKNOWN", [])
    return ("PASS", []) if v else ("FAIL", [{"Object":"Domain","Detail":"Privileged Access Management is disabled"}])

def load_recycle_bin_status(json_path: str) -> tuple[bool | None, str]:
    """
    Returns (enabled_bool_or_None, evidence_string).
    Supports multiple shapes:
      - {"RecycleBinEnabled": true/false}
      - {"Name":"Recycle Bin Feature","EnabledScopes":[...]}
      - {"ForestDN":"DC=...","EnabledScopes":[...]}
    """
    if not os.path.exists(json_path):
        return None, "Domain_RecycleBin.json not found"

    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception as e:
        return None, f"Failed to read JSON: {e}"

    # 1) Our preferred simple flag
    if isinstance(data, dict) and "RecycleBinEnabled" in data:
        enabled = bool(data.get("RecycleBinEnabled"))
        return enabled, f"RecycleBinEnabled={enabled}"

    # 2) Get-ADOptionalFeature shape (EnabledScopes non-empty => enabled)
    if isinstance(data, dict) and "EnabledScopes" in data:
        scopes = data.get("EnabledScopes") or []
        enabled = bool(scopes)
        return enabled, f"EnabledScopes={scopes if scopes else '[]'}"

    # 3) Sometimes wrapped or nested
    if isinstance(data, dict):
        # e.g. {"Result": {"EnabledScopes":[...]}}
        for k, v in data.items():
            if isinstance(v, dict) and "EnabledScopes" in v:
                scopes = v.get("EnabledScopes") or []
                enabled = bool(scopes)
                return enabled, f"{k}.EnabledScopes={scopes if scopes else '[]'}"

    # 4) Unknown shape -> unable to determine
    return None, "Unrecognized JSON structure; expected RecycleBinEnabled or EnabledScopes"

def check_bitlocker_key_not_in_ad():
    if BITLOCKER_STORE_AD is True:
        return ("PASS", [])
    if BITLOCKER_STORE_AD is False:
        return ("FAIL", [{
            "Object":"GPO",
            "Detail":"‘Store BitLocker recovery information in AD DS’ is NOT enabled (FVE ActiveDirectoryBackup)."
        }])
    return ("UNKNOWN", [])


def check_laps_not_installed():
    installed = any_computer_has_laps_signals()
    return ("PASS", []) if installed else ("FAIL", [{"Object":"Environment","Detail":"No evidence of LAPS (AdmPwd/msLAPS attributes or LAPS GPO)"}])

def check_krbtgt_pwd_old():
    bad, details = krbtgt_password_age_over(KRBTGT_MAX_AGE_DAYS)
    if details is None: return ("UNKNOWN", [])
    return ("FAIL", details) if bad else ("PASS", [])

def check_recycle_bin_not_enabled():
    enabled, evidence = load_recycle_bin_status(DOMAIN_RECYCLEBIN_JSON)

    # Could not determine from the provided file
    if enabled is None:
        return ("UNKNOWN", [{"Object": "Domain", "Detail": f"Needs additional data: {evidence}"}])

    # If enabled, the “not enabled” check PASSES (i.e., no risk)
    if enabled is True:
        return ("PASS", [])

    # If explicitly disabled, FAIL
    return ("FAIL", [{"Object": "Domain", "Detail": f"Recycle Bin is disabled ({evidence})"}])

def check_pso_misconfig():
    # Needs dedicated PSO export (msDS-PasswordSettings). Without it, don’t guess.
    return ("UNKNOWN", [])

# ========= run =========
CHECKS = [
    ("weak_encryption_dcs",      check_weak_encryption_dcs),      # High  (40)
    ("laps_not_installed",       check_laps_not_installed),       # Med   (32)
    ("weak_kerberos_algos",      check_weak_kerberos_algos),      # Med   (32)
    ("bitlocker_key_not_in_ad",  check_bitlocker_key_not_in_ad),  # Med   (24)
    ("krbtgt_pwd_old",           check_krbtgt_pwd_old),           # Med   (24)
    ("functional_level_low",     check_functional_level_low),     # Med   (18)
    ("pso_misconfig",            check_pso_misconfig),            # Med   (18)
    ("pam_not_enabled",          check_pam_not_enabled),          # Med   (18)
    ("recycle_bin_not_enabled",  check_recycle_bin_not_enabled),  # Low   (8)
]

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
        "status": status,            # PASS / FAIL / UNKNOWN
        "fail_items": len(details),
        "details": details,
    }
    results.append(rec)
    if status == "FAIL":
        failed_by_sev[meta["severity"]].append(rec)

# ========= print report =========
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

print("\n=== Category 2: Optional Feature & Domain Configuration (Runtime Report) ===")
print(f"Checks evaluated: {total}")
print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
print(f"Category 2 Total Risk Score: {category_risk_total}")
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
print()

def run_category2(input_dir: str):
    """
    Wrapper for Category 2: Optional Feature & Domain Configuration
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
    lines.append("=== Category 2: Optional Feature & Domain Configuration (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 2 Total Risk Score: {category_risk_total}")
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
