#!/usr/bin/env python3
import os, json
from typing import Any, Dict, List
from collections import Counter, defaultdict

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
GPO_FILE  = "nexora.local_gpos.json"

PRINT_MAX_DETAILS = 10

# ========= Risk model (Category 10) =========
CHECK_META = {
    # High Risks
    "firewall_disabled":     {"title":"Firewall disabled","severity":"High","score":75},
    "wdigest_enabled":       {"title":"WDigest authentication enabled","severity":"High","score":75},
    "lm_hash_storage":       {"title":"LM hash storage enabled","severity":"High","score":60},
    "ntlmv2_not_enforced":   {"title":"NTLMv2 not enforced","severity":"High","score":60},
    "gpp_autologon":         {"title":"gpp_autologon enabled","severity":"High","score":60},
    "lsass_unprotected":     {"title":"LSASS not running as protected process","severity":"High","score":60},
    "rdp_no_nla":            {"title":"RDP not using NLA","severity":"High","score":60},
    "rdp_not_secured_pth":   {"title":"RDP not secured against pass-the-hash","severity":"High","score":60},

    # Medium Risks
    "credential_guard_off":  {"title":"Credential Guard not enabled","severity":"Medium","score":48},
    "bitlocker_off":         {"title":"BitLocker not enabled","severity":"Medium","score":48},
    "powershell_v2":         {"title":"PowerShell v2 enabled","severity":"Medium","score":48},
    "llmnr_enabled":         {"title":"LLMNR/NetBIOS/mDNS enabled","severity":"Medium","score":48},
    "uac_insecure":          {"title":"UAC configuration insecure","severity":"Medium","score":48},
    "wpad_enabled":          {"title":"WPAD not disabled","severity":"Medium","score":48},
    "amsi_missing":          {"title":"AMSI not installed","severity":"Medium","score":48},
    "applocker_missing":     {"title":"AppLocker rules not defined","severity":"Medium","score":36},
    "ps_events_not_logged":  {"title":"PowerShell events not logged","severity":"Medium","score":36},
    "ps_not_restricted":     {"title":"PowerShell not in restricted mode","severity":"Medium","score":36},

    # Low Risks
    "force_logoff_hours":    {"title":"Force logoff when logon hours expire","severity":"Low","score":18},
    "msi_privileges":        {"title":"MSI packages always installed with elevated privileges","severity":"Low","score":27},
    "lsa_cache":             {"title":"Too many logons in LSA cache","severity":"Low","score":27},
    "ipv4_preferred":        {"title":"IPv4 preferred over IPv6","severity":"Low","score":12},
    "rdp_timeout":           {"title":"RDP session timeout too short","severity":"Low","score":18},
    "wsus_missing":          {"title":"WSUS server not used","severity":"Low","score":27},
    "wsh_enabled":           {"title":"Windows Script Host not disabled","severity":"Low","score":27},
}

# ========= registry map =========
REGISTRY_MAP = {
    # High
    "firewall_disabled":     ("HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\EnableFirewall", 1, True),
    "wdigest_enabled":       ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential", 0, True),
    "lm_hash_storage":       ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash", 1, True),
    "ntlmv2_not_enforced":   ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel", 5, True),
    "gpp_autologon":         ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon", 0, True),
    "lsass_unprotected":     ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL", 1, True),
    "rdp_no_nla":            ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication", 1, True),
    "rdp_not_secured_pth":   ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin", 0, False),

    # Medium
    "credential_guard_off":  ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags", 1, True),
    "bitlocker_off":         ("HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\EnableBDEWithNoTPM", 1, True),
    "powershell_v2":         ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\EnablePSRemotingV2", 0, True),
    "llmnr_enabled":         ("HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast", 0, True),
    "uac_insecure":          ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin", 2, True),
    "wpad_enabled":          ("HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\EnableAutoproxyResultCache", 0, True),
    "amsi_missing":          ("HKLM\\SOFTWARE\\Microsoft\\AMSI\\Enable", 1, True),
    "applocker_missing":     ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2", None, True),
    "ps_events_not_logged":  ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", 1, True),
    "ps_not_restricted":     ("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy", "AllSigned", True),

    # Low
    "force_logoff_hours":    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ForceLogoffWhenHourExpire", 1, True),
    "msi_privileges":        ("HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated", 0, True),
    "lsa_cache":             ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\CachedLogonsCount", 10, True),
    "ipv4_preferred":        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents", 0, True),
    "rdp_timeout":           ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\IdleTimeout", 900000, True),
    "wsus_missing":          ("HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\UseWUServer", 1, True),
    "wsh_enabled":           ("HKLM\\Software\\Microsoft\\Windows Script Host\\Settings\\Enabled", 0, True),
}

# ========= helpers =========
def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path,"r",encoding="utf-8-sig") as f:
        data=json.load(f)
    if isinstance(data,dict) and "data" in data: return data["data"]
    return data if isinstance(data,list) else []

def prop(d: Dict[str,Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key,default)

def eval_setting(gpos: List[Dict[str,Any]], reg_path: str, secure_value: Any, fail_if_equal=True):
    for g in gpos:
        reg_settings = g.get("RegistrySettings", [])
        for rs in reg_settings:
            path = (rs.get("Key","") + "\\" + rs.get("ValueName","")).lower()
            if reg_path.lower() in path:
                val = rs.get("Data")
                if secure_value is None:  # presence check
                    if val:
                        return "PASS",[],False
                    else:
                        return "FAIL",[{"Object":prop(g,"name","<GPO>"),"Detail":"Missing"}],False
                if fail_if_equal:
                    return ("PASS",[],False) if val == secure_value else ("FAIL",[{"Object":prop(g,"name","<GPO>"),"Detail":f"{reg_path}={val}"}],False)
                else:
                    return ("FAIL",[{"Object":prop(g,"name","<GPO>"),"Detail":f"{reg_path}={val}"}],False) if val == secure_value else ("PASS",[],False)
    # no matching registry found → treat as UNKNOWN (FAIL)
    return "FAIL",[{"Object":"N/A","Detail":f"{reg_path} not found"}],True

# ========= Wrapper for Streamlit =========
def run_category10(input_dir: str):
    gpos = load_json(os.path.join(input_dir, GPO_FILE))

    results=[]
    failed_by_sev={"High":[],"Medium":[],"Low":[]}
    unknown_items=[]

    for key, meta in CHECK_META.items():
        reg_path, secure_value, fail_if_equal = REGISTRY_MAP.get(key, (None,None,True))
        status,details,is_unknown=eval_setting(gpos,reg_path,secure_value,fail_if_equal)

        rec={"key":key,"title":meta["title"],"severity":meta["severity"],
             "score":meta["score"],"status":status,"fail_items":len(details),
             "details":details}
        results.append(rec)

        if status=="FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    total=len(results)
    failed_total=sum(1 for r in results if r["status"]=="FAIL")
    unknown_total=len(unknown_items)
    category_risk_total=sum(r["score"] for r in results if r["status"]=="FAIL")

    risk_by_severity={"High":0,"Medium":0,"Low":0}
    for r in results:
        if r["status"]=="FAIL":
            risk_by_severity[r["severity"]]+=r["score"]

    # --- Build console text ---
    lines=[]
    lines.append("=== Category 10: GPO & Security Settings (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 10 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    for sev in ["High","Medium","Low"]:
        items=failed_by_sev[sev]
        if not items: lines.append(f"{sev}: (none)"); continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    lines.append("Non-passing (UNKNOWN) checks (counted as FAIL):")
    for r in unknown_items:
        lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> additional data required")

    report_text="\n".join(lines)

    summary={
        "High":len(failed_by_sev["High"]),
        "Medium":len(failed_by_sev["Medium"]),
        "Low":len(failed_by_sev["Low"]),
        "TotalFails":failed_total,
        "Unknown":unknown_total,
        "RiskScore":category_risk_total,
    }

    return report_text, summary

if __name__=="__main__":
    text, summary = run_category10(INPUT_DIR)
    print(text)
    print(summary)
