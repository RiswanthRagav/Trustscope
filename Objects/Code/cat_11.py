#!/usr/bin/env python3
# cat_10_xml.py — Group Policy & Security Settings (XML-based, import-safe, auto-path)
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple, Optional

# How many failing details to print (0 = unlimited)
PRINT_MAX_DETAILS = 10

# Tunables
MAX_LSA_CACHED_LOGONS = 10          # >10 = FAIL
RDP_MIN_IDLE_MS       = 15 * 60 * 1000  # 15 minutes

# ===================== CHECKS (scores/severity) =====================
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

# ===================== utils: locating files =====================
def _resolve_base_dir(base_hint: Optional[str | Path]) -> Path:
    """Prefer caller-provided dir; otherwise try Objects/Domain Data relatives."""
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():  # a directory
            return p
        if p.is_file():  # a file; use parent
            return p.parent

    code_dir = Path(__file__).resolve().parent              # e.g., .../Objects/Code
    objects_dir = code_dir.parent                           # e.g., .../Objects
    for cand in [
        objects_dir / "Domain Data",
        objects_dir / "DomainData",
        objects_dir / "domain data",
        objects_dir / "data",
        objects_dir,
    ]:
        if cand.exists() and cand.is_dir():
            return cand
    return objects_dir

def _find_xml(base: Path, filename: str) -> Optional[Path]:
    """Look for XML in base and one level up; tolerate exact name or common variants."""
    candidates = [
        base / filename,
        base / filename.lower(),
        base / filename.upper(),
        base.parent / filename,
    ]
    for c in candidates:
        if c.exists():
            return c
    return None

# ===================== XML PARSER =====================
def _parse_registry_entries(xml_path: Path) -> List[Dict[str, Any]]:
    """Collect <Registry> items; return dicts with key/value_name/num/boo/str (lowercased)."""
    out: List[Dict[str, Any]] = []
    if not xml_path or not xml_path.exists():
        return out
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        def local(tag: str) -> str: return tag.split('}')[-1].lower()
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
                        try: data["num"] = int(val)
                        except: pass
                    elif nm == "settingboolean":
                        if val != "": data["boo"] = (val.lower() == "true")
                    elif nm in ("settingstring", "settingtext", "value"):
                        data["str"] = val
                if data["key"] and data["value_name"]:
                    out.append(data)
    except Exception:
        pass
    return out

def _merge_registry_lists(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    for lst in lists:
        merged.extend(lst or [])
    return merged

# ===================== registry helpers (pure) =====================
def _find_reg_values(REG: List[Dict[str, Any]], key_contains: str, value_name: str) -> List[Dict[str, Any]]:
    kc = key_contains.lower()
    vn = value_name.lower()
    return [r for r in REG if kc in (r.get("key","")) and r.get("value_name","") == vn]

def _pick_value(entry: Dict[str, Any]) -> Optional[Any]:
    if entry.get("num") is not None: return entry["num"]
    if entry.get("boo") is not None: return 1 if entry["boo"] else 0
    if entry.get("str") is not None: return entry["str"]
    return None

def _first_value(REG: List[Dict[str, Any]], key_contains: str, value_name: str) -> Optional[Any]:
    hits = _find_reg_values(REG, key_contains, value_name)
    for h in hits:
        v = _pick_value(h)
        if v is not None:
            return v
    return None

# ===================== tiny helpers for checks =====================
def PASS():     return ("PASS", [])
def FAIL(msg):  return ("FAIL", [{"Object":"GPO/Registry", "Detail": msg}])
def UNKNOWN():  return ("UNKNOWN", [])

# ===================== checks factory =====================
def _make_checks(REG: List[Dict[str, Any]]) -> List[Tuple[str, Any]]:
    # local aliases to bind REG
    first_value = lambda k, v: _first_value(REG, k, v)

    def check_force_logoff_hours():
        v = first_value(r"system\currentcontrolset\services\lanmanserver\parameters", "enableforcedlogoff")
        if v is None:
            v = first_value(r"system\currentcontrolset\services\lanmanserver\parameters", "forcelogoffwhenhourexpire")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 1 else FAIL(f"EnableForcedLogOff={v}")

    def check_msi_always_install_elevated():
        bad = []
        for hive_key in [r"software\policies\microsoft\windows\installer"]:
            v = first_value(hive_key, "alwaysinstallelevated")
            if v is not None and int(v) == 1:
                bad.append(f"{hive_key}\\AlwaysInstallElevated=1")
        if not bad and first_value(r"software\policies\microsoft\windows\installer", "alwaysinstallelevated") is None:
            return UNKNOWN()
        return FAIL("; ".join(bad)) if bad else PASS()

    def check_credential_guard():
        v = first_value(r"system\currentcontrolset\control\deviceguard\scenarios\credentialguard", "enabled")
        if v is not None: return PASS() if int(v) >= 1 else FAIL(f"CredentialGuard Enabled={v}")
        l = first_value(r"system\currentcontrolset\control\lsa", "lsacfgflags")
        if l is not None: return PASS() if int(l) >= 1 else FAIL(f"LsaCfgFlags={l} (CG likely off)")
        return UNKNOWN()

    def check_no_lm_hash():
        v = first_value(r"system\currentcontrolset\control\lsa", "nolmhash")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 1 else FAIL(f"NoLMHash={v}")

    def check_ntlmv2():
        v = first_value(r"system\currentcontrolset\control\lsa", "lmcompatibilitylevel")
        if v is None: return UNKNOWN()
        return PASS() if int(v) >= 5 else FAIL(f"LmCompatibilityLevel={v} (<5)")

    def check_applocker():
        found_any = False
        any_enforced = False
        for r in REG:
            if r.get("key","").find(r"software\policies\microsoft\windows\srpv2") != -1 and r.get("value_name") == "enforcementmode":
                found_any = True
                v = _pick_value(r)
                if v is not None and int(v) > 0:
                    any_enforced = True
        if not found_any: return UNKNOWN()
        return PASS() if any_enforced else FAIL("SrpV2 EnforcementMode not > 0 for any rule-set")

    def check_gpp_autologon():
        v = first_value(r"software\microsoft\windows nt\currentversion\winlogon", "defaultpassword")
        if v is None: return UNKNOWN()
        if isinstance(v, str): return FAIL("DefaultPassword present in Winlogon") if v.strip() else PASS()
        return FAIL("DefaultPassword present in Winlogon")

    def check_bitlocker_enabled():
        CHECK_VALUES = [("usetpm",1), ("usetpmkey",1), ("usetpmpin",1),
                        ("encryptionmethodwithxtsos", None), ("encryptionmethodwithxtsfv", None),
                        ("fdvencryptiontype", None), ("rdvencryptiontype", None)]
        saw_any_fve = False
        saw_enforcement = False
        for r in REG:
            if r.get("key","").find(r"software\policies\microsoft\fve") != -1:
                saw_any_fve = True
                vn = r.get("value_name",""); v = _pick_value(r)
                for name, req in CHECK_VALUES:
                    if vn == name:
                        if req is None: saw_enforcement = True
                        else:
                            try:
                                if int(v) == int(req): saw_enforcement = True
                            except: pass
        if not saw_any_fve: return UNKNOWN()
        return PASS() if saw_enforcement else FAIL("No clear BitLocker enforcement values under Policies\\Microsoft\\FVE")

    def check_firewall():
        profiles = [
            (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\domainprofile",  "enablefirewall"),
            (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\standardprofile","enablefirewall"),
            (r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\publicprofile",  "enablefirewall"),
        ]
        saw_any = False; bad = []
        for k, vname in profiles:
            v = first_value(k, vname)
            if v is not None:
                saw_any = True
                if int(v) != 1:
                    bad.append(f"{k}\\{vname}={v}")
        if not saw_any: return UNKNOWN()
        return PASS() if not bad else FAIL("; ".join(bad))

    def check_ipv4_preferred():
        v = first_value(r"system\currentcontrolset\services\tcpip6\parameters", "disabledcomponents")
        if v is None: return UNKNOWN()
        try: iv = int(v)
        except: return UNKNOWN()
        return PASS() if iv == 32 else FAIL(f"DisabledComponents={iv} (expected 32 to prefer IPv4)")

    def check_llmnr_netbios_mdns():
        saw = False; bad = []
        v1 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablemulticast")
        v2 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablellmnr")
        if v1 is not None: saw = True;  bad += [] if int(v1) == 0 else ["LLMNR: EnableMulticast!=0"]
        if v2 is not None: saw = True;  bad += [] if int(v2) == 0 else ["LLMNR: EnableLLMNR!=0"]
        v3 = first_value(r"software\policies\microsoft\windows nt\dnsclient", "enablemdns")
        if v3 is not None: saw = True;  bad += [] if int(v3) == 0 else ["mDNS: EnableMDNS!=0"]
        return UNKNOWN() if not saw else (PASS() if not bad else FAIL("; ".join(bad)))

    def check_lsa_cached_logons():
        v = first_value(r"software\microsoft\windows nt\currentversion\winlogon", "cachedlogonscount")
        if v is None: return UNKNOWN()
        try: iv = int(v)
        except: return UNKNOWN()
        return PASS() if iv <= MAX_LSA_CACHED_LOGONS else FAIL(f"CachedLogonsCount={iv} (> {MAX_LSA_CACHED_LOGONS})")

    def check_lsass_ppl():
        v = first_value(r"system\currentcontrolset\control\lsa", "runasppl")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 1 else FAIL(f"RunAsPPL={v}")

    def check_powershell_v2():
        return UNKNOWN()

    def check_powershell_events():
        base = r"software\policies\microsoft\windows\powershell"
        sb  = first_value(base + r"\scriptblocklogging", "enablescriptblocklogging")
        ml  = first_value(base + r"\modulelogging", "enablemodulelogging")
        tr  = first_value(base + r"\transcription", "enabletranscripting")
        saw_any = any(v is not None for v in (sb, ml, tr))
        if not saw_any: return UNKNOWN()
        enabled = any(int(v or 0) == 1 for v in (sb, ml, tr))
        return PASS() if enabled else FAIL("None of ScriptBlock/Module/Transcription logging is enabled")

    def check_powershell_restricted():
        v = first_value(r"software\policies\microsoft\windows\powershell", "executionpolicy")
        if v is None: return UNKNOWN()
        s = str(v).strip().lower()
        return FAIL(f"ExecutionPolicy={v}") if s in ("unrestricted","bypass") else PASS()

    def check_rdp_nla():
        v = first_value(r"system\currentcontrolset\control\terminal server\winstations\rdp-tcp", "userauthentication")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 1 else FAIL(f"RDP UserAuthentication={v}")

    def check_rdp_restricted_admin():
        v = first_value(r"system\currentcontrolset\control\lsa", "disablerestrictedadmin")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 0 else FAIL(f"DisableRestrictedAdmin={v} (0 expected)")

    def check_rdp_session_timeout():
        v = first_value(r"system\currentcontrolset\control\terminal server\winstations\rdp-tcp", "maxidletime")
        if v is None: return UNKNOWN()
        try: iv = int(v)
        except: return UNKNOWN()
        return PASS() if iv >= RDP_MIN_IDLE_MS else FAIL(f"MaxIdleTime={iv}ms (< {RDP_MIN_IDLE_MS}ms)")

    def check_uac_secure():
        base = r"software\microsoft\windows\currentversion\policies\system"
        lua = first_value(base, "enablelua")
        psd = first_value(base, "promptonsecuredesktop")
        if lua is None and psd is None: return UNKNOWN()
        bad = []
        if lua is not None and int(lua) != 1: bad.append(f"EnableLUA={lua}")
        if psd is not None and int(psd) != 1: bad.append(f"PromptOnSecureDesktop={psd}")
        if bad: return FAIL("; ".join(bad))
        if lua is None or psd is None: return UNKNOWN()
        return PASS()

    def check_wdigest():
        v = first_value(r"system\currentcontrolset\control\securityproviders\wdigest", "uselogoncredential")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 0 else FAIL(f"UseLogonCredential={v}")

    def check_wpad_disabled():
        return UNKNOWN()

    def check_wsh_disabled():
        v = first_value(r"software\microsoft\windows script host\settings", "enabled")
        if v is None: return UNKNOWN()
        return PASS() if int(v) == 0 else FAIL(f"WSH Enabled={v} (expected 0)")

    def check_wsus_used():
        base = r"software\policies\microsoft\windows\windowsupdate"
        au   = base + r"\au"
        use  = first_value(au, "usewuserver")
        wus  = first_value(base, "wuserver")
        wuss = first_value(base, "wustatusserver")
        if use is None and wus is None and wuss is None: return UNKNOWN()
        try: usei = int(use) if use is not None else 0
        except: usei = 0
        if usei == 1 and (wus and str(wus).strip()) and (wuss and str(wuss).strip()):
            return PASS()
        return FAIL(f"UseWUServer={use}; WUServer={wus}; WUStatusServer={wuss}")

    def check_amsi():
        return UNKNOWN()

    return [
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

# ===================== public entrypoint =====================
def run_category10_xml(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Read GPO report XMLs (DefaultDomainPolicy.xml, AllGPOs.xml), evaluate hardening checks,
    and return (report_text, summary_dict). Safe to import in Streamlit.
    """
    base = _resolve_base_dir(input_dir)
    ddp  = _find_xml(base, "DefaultDomainPolicy.xml")
    allg = _find_xml(base, "AllGPOs.xml")

    reg1 = _parse_registry_entries(ddp) if ddp else []
    reg2 = _parse_registry_entries(allg) if allg else []
    REG  = _merge_registry_lists(reg1, reg2)

    CHECKS = _make_checks(REG)

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

    # Totals
    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r["status"] == "UNKNOWN")
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")

    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # Report text
    lines: List[str] = []
    lines.append("=== Category 10: Group Policy & Security Settings (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 10 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    def _block(sev: str, max_details: int = PRINT_MAX_DETAILS):
        items = failed_by_sev.get(sev, [])
        if not items:
            lines.append(f"{sev}: (none)")
            return
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            details = r["details"]
            if max_details and len(details) > max_details:
                for d in details[:max_details]:
                    lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
                lines.append(f"      ... and {len(details)-max_details} more")
            else:
                for d in details:
                    lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    _block("Medium"); _block("Low")

    lines.append("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r["status"] == "UNKNOWN":
            lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)
    summary = {
        "High":   len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low":    len(failed_by_sev["Low"]),
        "TotalFails": failed_total,
        "Unknown":    unknown_total,
        "RiskScore":  category_risk_total,
    }
    return report_text, summary


# Optional CLI smoke test
if __name__ == "__main__":
    txt, summ = run_category10_xml(None)  # auto-detect near /Objects
    print(txt)
    print("\nSummary:", summ)
