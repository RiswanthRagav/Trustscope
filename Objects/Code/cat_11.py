#!/usr/bin/env python3
import os
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple, Optional

# ===================== CONFIG =====================
INPUT_DIR       = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
ALL_GPOS_XML    = r"C:\Users\LENOVO\OneDrive\Desktop\AllGPOs.xml"
DDP_XML         = r"C:\Users\LENOVO\OneDrive\Desktop\DefaultDomainPolicy.xml"

# How many failing details to print (0 = unlimited)
PRINT_MAX_DETAILS = 10

# Tunables for thresholds
MAX_LSA_CACHED_LOGONS = 10     # >10 = FAIL
RDP_MIN_IDLE_MS = 15 * 60 * 1000  # 15 minutes

# ===================== CHECKS (scores/severity) =====================
# All are "Medium" unless noted. Tune scores if you have a scoring matrix.
CHECK_META = {
    # Network / Account policies
    "force_logoff_when_hours_expire_off":  {"title": "Force logoff when logon hours expire not enforced", "severity": "Medium", "score": 18},
    "msi_always_install_elevated":         {"title": "MSI packages always installed with elevated privileges", "severity": "Medium", "score": 32},
    "credential_guard_not_enabled":        {"title": "Credential Guard not enabled", "severity": "Medium", "score": 32},
    "lm_hash_storage_enabled":             {"title": "LM hash storage enabled", "severity": "Medium", "score": 32},
    "ntlmv2_not_enforced":                 {"title": "NTLMv2 not enforced", "severity": "Medium", "score": 32},
    "applocker_not_defined":               {"title": "AppLocker rules not defined", "severity": "Medium", "score": 24},
    "gpp_autologon_enabled":               {"title": "gpp_autologon enabled (DefaultPassword present)", "severity": "Medium", "score": 24},

    # Device / OS security
    "bitlocker_not_enabled":               {"title": "BitLocker not enabled via policy", "severity": "Medium", "score": 24},
    "firewall_disabled":                   {"title": "Firewall disabled (any profile)", "severity": "Medium", "score": 32},
    "ipv4_preferred_over_ipv6_off":        {"title": "IPv4 not preferred over IPv6", "severity": "Low", "score": 12},
    "llmnr_netbios_mdns_enabled":          {"title": "LLMNR / NetBIOS / mDNS enabled", "severity": "Medium", "score": 24},
    "too_many_cached_logons":              {"title": "Too many logons in LSA cache", "severity": "Medium", "score": 18},
    "lsass_not_ppl":                       {"title": "LSASS not running as protected process (PPL)", "severity": "Medium", "score": 32},

    # PowerShell hardening
    "ps_v2_enabled":                       {"title": "PowerShell v2 enabled", "severity": "Medium", "score": 18},
    "ps_events_not_logged":                {"title": "PowerShell events not logged (ScriptBlock/Module/Transcription)", "severity": "Medium", "score": 24},
    "ps_not_restricted":                   {"title": "PowerShell not in a restricted execution policy", "severity": "Medium", "score": 18},

    # RDP
    "rdp_not_using_nla":                   {"title": "RDP not using NLA", "severity": "Medium", "score": 24},
    "rdp_not_restricted_admin":            {"title": "RDP not secured against pass-the-hash (Restricted Admin off)", "severity": "Medium", "score": 24},
    "rdp_session_timeout_too_short":       {"title": "RDP session timeout too short", "severity": "Low", "score": 12},

    # UAC / Auth
    "uac_insecure":                        {"title": "UAC configuration insecure", "severity": "Medium", "score": 24},
    "wdigest_enabled":                     {"title": "WDigest authentication enabled", "severity": "Medium", "score": 32},
    "wpad_not_disabled":                   {"title": "WPAD not disabled", "severity": "Low", "score": 12},
    "wsh_not_disabled":                    {"title": "Windows Script Host not disabled", "severity": "Low", "score": 12},
    "wsus_not_used":                       {"title": "WSUS server not used", "severity": "Medium", "score": 18},
    "amsi_not_installed":                  {"title": "AMSI not installed/enforced", "severity": "Medium", "score": 18},
}

# ===================== XML PARSER =====================
def parse_registry_entries(xml_path: str) -> List[Dict[str, Any]]:
    """
    Collects every <*Registry*> item from a GPO report (any namespace).
    Tries to read: Key, ValueName, SettingNumber, SettingBoolean, SettingString.
    Returns a list of dicts with normalized lowercase key/value_name.
    """
    out: List[Dict[str, Any]] = []
    if not os.path.exists(xml_path):
        return out

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        def local(tag: str) -> str:
            return tag.split('}')[-1].lower()

        for el in root.iter():
            if local(el.tag) == "registry":
                data = {"key": None, "value_name": None, "num": None, "boo": None, "str": None}
                for child in list(el):
                    nm = local(child.tag)
                    val = (child.text or "").strip()
                    if nm == "key":
                        data["key"] = val.lower()
                    elif nm in ("valuename", "valuedisplayname", "valuenameid"):
                        data["value_name"] = val.lower()
                    elif nm == "settingnumber":
                        try:
                            data["num"] = int(val)
                        except Exception:
                            pass
                    elif nm == "settingboolean":
                        if val != "":
                            data["boo"] = (val.lower() == "true")
                    elif nm in ("settingstring", "settingtext", "value"):
                        data["str"] = val

                if data["key"] and data["value_name"]:
                    out.append(data)

    except Exception:
        # fall through with whatever we captured
        pass

    return out

def merge_registry_lists(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    for lst in lists:
        merged.extend(lst or [])
    return merged

# Load & merge XML registry items
reg1 = parse_registry_entries(DDP_XML)
reg2 = parse_registry_entries(ALL_GPOS_XML)
REG = merge_registry_lists(reg1, reg2)

# ===================== Registry Helpers =====================
def find_reg_values(key_contains: str, value_name: str) -> List[Dict[str, Any]]:
    """Return all entries where key contains substring and value_name matches (case-insensitive)."""
    kc = key_contains.lower()
    vn = value_name.lower()
    hits = []
    for r in REG:
        if r.get("key","").find(kc) != -1 and r.get("value_name","") == vn:
            hits.append(r)
    return hits

def pick_value(entry: Dict[str, Any]) -> Optional[Any]:
    """Return the best-typed value from a parsed registry entry."""
    if entry.get("num") is not None:
        return entry["num"]
    if entry.get("boo") is not None:
        # normalize booleans to 1/0 for simple comparisons
        return 1 if entry["boo"] else 0
    if entry.get("str") is not None:
        return entry["str"]
    return None

def first_value(key_contains: str, value_name: str) -> Optional[Any]:
    hits = find_reg_values(key_contains, value_name)
    for h in hits:
        v = pick_value(h)
        if v is not None:
            return v
    return None

def any_value_equals(key_contains: str, value_name: str, target: Any) -> Optional[bool]:
    hits = find_reg_values(key_contains, value_name)
    if not hits:
        return None
    for h in hits:
        v = pick_value(h)
        if v == target:
            return True
    return False if hits else None

# ===================== Check functions =====================
def PASS():   return ("PASS", [])
def FAIL(msg): return ("FAIL", [{"Object":"GPO/Registry", "Detail": msg}])
def UNKNOWN(): return ("UNKNOWN", [])

# 1) Force logoff when logon hours expire (EnableForcedLogOff=1)
def check_force_logoff_hours():
    v = first_value(r"system\currentcontrolset\services\lanmanserver\parameters", "enableforcedlogoff")
    if v is None:
        # Alternate name sometimes used
        v = first_value(r"system\currentcontrolset\services\lanmanserver\parameters", "forcelogoffwhenhourexpire")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 1 else FAIL(f"EnableForcedLogOff={v}")

# 2) MSI AlwaysInstallElevated (1 is BAD)
def check_msi_always_install_elevated():
    bad = False
    hits = []
    for hive_key in [
        r"software\policies\microsoft\windows\installer",   # HKLM
        r"software\policies\microsoft\windows\installer",   # HKCU would also appear as 'User' GPO entries in XML if present
    ]:
        v = first_value(hive_key, "alwaysinstallelevated")
        if v is not None:
            if int(v) == 1:
                bad = True
                hits.append(f"{hive_key}\\AlwaysInstallElevated=1")
    if not hits and all(first_value(hk, "alwaysinstallelevated") is None for hk in [r"software\policies\microsoft\windows\installer"]):
        return UNKNOWN()
    return FAIL("; ".join(hits)) if bad else PASS()

# 3) Credential Guard enabled
def check_credential_guard():
    # Use DeviceGuard scenario key if present
    v = first_value(r"system\currentcontrolset\control\deviceguard\scenarios\credentialguard", "enabled")
    if v is not None:
        return PASS() if int(v) >= 1 else FAIL(f"CredentialGuard Enabled={v}")
    # Alt: LsaCfgFlags (legacy enable)
    l = first_value(r"system\currentcontrolset\control\lsa", "lsacfgflags")
    if l is not None:
        return PASS() if int(l) >= 1 else FAIL(f"LsaCfgFlags={l} (CG likely off)")
    return UNKNOWN()

# 4) NoLMHash = 1 (secure)
def check_no_lm_hash():
    v = first_value(r"system\currentcontrolset\control\lsa", "nolmhash")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 1 else FAIL(f"NoLMHash={v}")

# 5) NTLMv2 enforced (LmCompatibilityLevel >= 5)
def check_ntlmv2():
    v = first_value(r"system\currentcontrolset\control\lsa", "lmcompatibilitylevel")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) >= 5 else FAIL(f"LmCompatibilityLevel={v} (<5)")

# 6) AppLocker enforcement present (any SrpV2 EnforcementMode > 0)
def check_applocker():
    found_any = False
    any_enforced = False
    for r in REG:
        if r.get("key","").find(r"software\policies\microsoft\windows\srpv2") != -1 and r.get("value_name") == "enforcementmode":
            found_any = True
            v = pick_value(r)
            if v is not None and int(v) > 0:
                any_enforced = True
    if not found_any:
        return UNKNOWN()
    return PASS() if any_enforced else FAIL("SrpV2 EnforcementMode not > 0 for any rule-set")

# 7) gpp_autologon: DefaultPassword present -> FAIL
def check_gpp_autologon():
    v = first_value(r"software\microsoft\windows nt\currentversion\winlogon", "defaultpassword")
    if v is None:
        return UNKNOWN()
    if isinstance(v, str):
        return FAIL("DefaultPassword present in Winlogon") if v.strip() != "" else PASS()
    return FAIL("DefaultPassword present in Winlogon")

# 8) BitLocker policy presence (very conservative)
def check_bitlocker_enabled():
    # PASS if we see policy keys indicating BitLocker enforcement
    CHECK_VALUES = [
        ("usetpm", 1),
        ("usetpmkey", 1),
        ("usetpmpin", 1),
        ("encryptionmethodwithxtsos", None),  # presence is signal enough
        ("encryptionmethodwithxtsfv", None),
        ("fdvencryptiontype", None),
        ("rdvencryptiontype", None),
    ]
    saw_any_fve = False
    saw_enforcement = False
    for r in REG:
        if r.get("key","").find(r"software\policies\microsoft\fve") != -1:
            saw_any_fve = True
            vn = r.get("value_name","")
            v  = pick_value(r)
            for name, req in CHECK_VALUES:
                if vn == name:
                    if req is None:
                        saw_enforcement = True
                    else:
                        try:
                            if int(v) == int(req):
                                saw_enforcement = True
                        except Exception:
                            pass
    if not saw_any_fve:
        return UNKNOWN()
    return PASS() if saw_enforcement else FAIL("No clear BitLocker enforcement values found under Policies\\Microsoft\\FVE")

# 9) Firewall profiles must be enabled (Domain/Private/Public)
def check_firewall():
    profiles = [
        (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\domainprofile",  "enablefirewall"),
        (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\standardprofile","enablefirewall"),
        (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\publicprofile",  "enablefirewall"),
    ]
    saw_any = False
    bad = []
    for k, vname in profiles:
        v = first_value(k, vname)
        if v is not None:
            saw_any = True
            if int(v) != 1:
                bad.append(f"{k}\\{vname}={v}")
    if not saw_any:
        return UNKNOWN()
    return PASS() if not bad else FAIL("; ".join(bad))

# 10) IPv4 preferred over IPv6 (DisabledComponents=0x20)
def check_ipv4_preferred():
    v = first_value(r"system\currentcontrolset\services\tcpip6\parameters", "disabledcomponents")
    if v is None:
        return UNKNOWN()
    try:
        iv = int(v)
    except Exception:
        return UNKNOWN()
    return PASS() if iv == 32 else FAIL(f"DisabledComponents={iv} (expected 32 to prefer IPv4)")

# 11) LLMNR / NetBIOS / mDNS enabled
def check_llmnr_netbios_mdns():
    saw = False
    bad = []
    # LLMNR - Policies\Windows NT\DNSClient: EnableMulticast=0 or EnableLLMNR=0 is good; 1 is bad.
    v1 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablemulticast")
    v2 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablellmnr")
    if v1 is not None:
        saw = True
        if int(v1) != 0:
            bad.append("LLMNR: EnableMulticast!=0")
    if v2 is not None:
        saw = True
        if int(v2) != 0:
            bad.append("LLMNR: EnableLLMNR!=0")
    # mDNS (if present)
    v3 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablemdns")
    if v3 is not None:
        saw = True
        if int(v3) != 0:
            bad.append("mDNS: EnableMDNS!=0")
    # NetBIOS (GPO direct registry rarely present; skip if not found)
    return UNKNOWN() if not saw else (PASS() if not bad else FAIL("; ".join(bad)))

# 12) Too many logons kept in LSA cache (CachedLogonsCount <= threshold)
def check_lsa_cached_logons():
    v = first_value(r"software\microsoft\windows nt\currentversion\winlogon", "cachedlogonscount")
    if v is None:
        return UNKNOWN()
    try:
        iv = int(v)
    except Exception:
        return UNKNOWN()
    return PASS() if iv <= MAX_LSA_CACHED_LOGONS else FAIL(f"CachedLogonsCount={iv} (> {MAX_LSA_CACHED_LOGONS})")

# 13) LSASS runs as protected process (RunAsPPL=1)
def check_lsass_ppl():
    v = first_value(r"system\currentcontrolset\control\lsa", "runasppl")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 1 else FAIL(f"RunAsPPL={v}")

# 14) PowerShell v2 disabled (we mark UNKNOWN unless explicit disable key present)
def check_powershell_v2():
    # There isn't a reliable GPO registry for "PSv2 removed". If we ever see an explicit disable flag, pass; else unknown.
    # Some environments set: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\EnablePSRemoting or features, but not definitive.
    return UNKNOWN()

# 15) PowerShell events logged: ScriptBlock OR Module OR Transcription enabled
def check_powershell_events():
    base = r"software\policies\microsoft\windows\powershell"
    sb  = first_value(base + r"\scriptblocklogging", "enablescriptblocklogging")
    ml  = first_value(base + r"\modulelogging", "enablemodulelogging")
    tr  = first_value(base + r"\transcription", "enabletranscripting")
    saw_any = any(v is not None for v in (sb, ml, tr))
    if not saw_any:
        return UNKNOWN()
    enabled = any(int(v or 0) == 1 for v in (sb, ml, tr))
    return PASS() if enabled else FAIL("None of ScriptBlock/Module/Transcription logging is enabled")

# 16) PowerShell restricted execution policy (ExecutionPolicy not Unrestricted/Bypass)
def check_powershell_restricted():
    v = first_value(r"software\policies\microsoft\windows\powershell", "executionpolicy")
    if v is None:
        return UNKNOWN()
    s = str(v).strip().lower()
    return FAIL(f"ExecutionPolicy={v}") if s in ("unrestricted","bypass") else PASS()

# 17) RDP using NLA (UserAuthentication=1)
def check_rdp_nla():
    v = first_value(r"system\currentcontrolset\control\terminal server\winstations\rdp-tcp", "userauthentication")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 1 else FAIL(f"RDP UserAuthentication={v}")

# 18) RDP Restricted Admin enabled (DisableRestrictedAdmin=0)
def check_rdp_restricted_admin():
    v = first_value(r"system\currentcontrolset\control\lsa", "disablerestrictedadmin")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 0 else FAIL(f"DisableRestrictedAdmin={v} (0 expected)")

# 19) RDP session timeout (MaxIdleTime >= threshold)
def check_rdp_session_timeout():
    v = first_value(r"system\currentcontrolset\control\terminal server\winstations\rdp-tcp", "maxidletime")
    if v is None:
        return UNKNOWN()
    try:
        iv = int(v)
    except Exception:
        return UNKNOWN()
    return PASS() if iv >= RDP_MIN_IDLE_MS else FAIL(f"MaxIdleTime={iv}ms (< {RDP_MIN_IDLE_MS}ms)")

# 20) UAC secure: EnableLUA=1 AND PromptOnSecureDesktop=1 (simple baseline)
def check_uac_secure():
    base = r"software\microsoft\windows\currentversion\policies\system"
    lua = first_value(base, "enablelua")
    psd = first_value(base, "promptonsecuredesktop")
    if lua is None and psd is None:
        return UNKNOWN()
    bad = []
    if lua is not None and int(lua) != 1:
        bad.append(f"EnableLUA={lua}")
    if psd is not None and int(psd) != 1:
        bad.append(f"PromptOnSecureDesktop={psd}")
    if bad:
        return FAIL("; ".join(bad))
    # If one present and secure, and the other missing, we play safe → UNKNOWN
    if lua is None or psd is None:
        return UNKNOWN()
    return PASS()

# 21) WDigest UseLogonCredential=0
def check_wdigest():
    v = first_value(r"system\currentcontrolset\control\securityproviders\wdigest", "uselogoncredential")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 0 else FAIL(f"UseLogonCredential={v}")

# 22) WPAD disabled (no robust single policy key → UNKNOWN unless explicit block present)
def check_wpad_disabled():
    # Without a reliable, single policy knob in the GPO XML, mark unknown.
    return UNKNOWN()

# 23) Windows Script Host disabled: Enabled=0 under WSH Settings
def check_wsh_disabled():
    v = first_value(r"software\microsoft\windows script host\settings", "enabled")
    if v is None:
        return UNKNOWN()
    return PASS() if int(v) == 0 else FAIL(f"WSH Enabled={v} (expected 0)")

# 24) WSUS in use: UseWUServer=1 and WUServer/WUStatusServer set
def check_wsus_used():
    base = r"software\policies\microsoft\windows\windowsupdate"
    au   = base + r"\au"
    use  = first_value(au, "usewuserver")
    wus  = first_value(base, "wuserver")
    wuss = first_value(base, "wustatusserver")
    if use is None and wus is None and wuss is None:
        return UNKNOWN()
    try:
        usei = int(use) if use is not None else 0
    except Exception:
        usei = 0
    if usei == 1 and (wus and str(wus).strip()) and (wuss and str(wuss).strip()):
        return PASS()
    return FAIL(f"UseWUServer={use}; WUServer={wus}; WUStatusServer={wuss}")

# 25) AMSI present/enforced (no single reliable GPO key → UNKNOWN)
def check_amsi():
    return UNKNOWN()

# ===================== Run all =====================
CHECKS: List[Tuple[str, Any]] = [
    ("force_logoff_when_hours_expire_off",  check_force_logoff_hours),
    ("msi_always_install_elevated",         check_msi_always_install_elevated),
    ("credential_guard_not_enabled",        check_credential_guard),
    ("lm_hash_storage_enabled",             check_no_lm_hash),
    ("ntlmv2_not_enforced",                 check_ntlmv2),
    ("applocker_not_defined",               check_applocker),
    ("gpp_autologon_enabled",               check_gpp_autologon),

    ("bitlocker_not_enabled",               check_bitlocker_enabled),
    ("firewall_disabled",                   check_firewall),
    ("ipv4_preferred_over_ipv6_off",        check_ipv4_preferred),
    ("llmnr_netbios_mdns_enabled",          check_llmnr_netbios_mdns),
    ("too_many_cached_logons",              check_lsa_cached_logons),
    ("lsass_not_ppl",                       check_lsass_ppl),

    ("ps_v2_enabled",                       check_powershell_v2),
    ("ps_events_not_logged",                check_powershell_events),
    ("ps_not_restricted",                   check_powershell_restricted),

    ("rdp_not_using_nla",                   check_rdp_nla),
    ("rdp_not_restricted_admin",            check_rdp_restricted_admin),
    ("rdp_session_timeout_too_short",       check_rdp_session_timeout),

    ("uac_insecure",                        check_uac_secure),
    ("wdigest_enabled",                     check_wdigest),
    ("wpad_not_disabled",                   check_wpad_disabled),
    ("wsh_not_disabled",                    check_wsh_disabled),
    ("wsus_not_used",                       check_wsus_used),
    ("amsi_not_installed",                  check_amsi),
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
            "status": status,         # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    # ===== Runtime report =====
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

    print("\n=== Category 10: Group Policy & Security Settings (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 10 Total Risk Score: {category_risk_total}")
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
    print_failed_block("Low")

    print("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r["status"] == "UNKNOWN":
            print(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")
    print()



if __name__ == "__main__":
    main()
