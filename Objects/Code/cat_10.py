#!/usr/bin/env python3
# cat_10.py — GPO & Security Settings (auto path + import-safe)
from __future__ import annotations

import os, json
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from collections import Counter, defaultdict

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

GPO_FILE = "nexora.local_gpos.json"

# registry setting map:
#   key -> (full_reg_path_substring_to_match, secure_value, fail_if_equal)
REGISTRY_MAP: Dict[str, Tuple[Any, Any, bool]] = {
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
    "applocker_missing":     ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2", None, True),  # presence check
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

# ========= Path resolver =========
def _resolve_input_dir_prefer_domain_data(base_hint: Optional[str | Path]) -> Path:
    """
    Resolve the folder that contains your Nexora JSONs.
    Priority:
      1) base_hint (if provided and exists)
      2) .../Objects/Domain Data (and variants)
      3) .../Objects/data, then .../Objects
    """
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():  return p
        if p.is_file(): return p.parent

    code_dir = Path(__file__).resolve().parent      # .../Objects/Code
    objects_dir = code_dir.parent                   # .../Objects

    for c in [
        objects_dir / "Domain Data",
        objects_dir / "DomainData",
        objects_dir / "domain data",
        objects_dir / "data",
        objects_dir,
    ]:
        if c.exists() and c.is_dir():
            return c
    return objects_dir

# ========= helpers =========
def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return data if isinstance(data, list) else []

def prop(d: Dict[str,Any] | None, key: str, default=None):
    if not isinstance(d, dict):
        return default
    return (d.get("Properties") or {}).get(key, default)

def _iter_registry_items(gpo_obj: Dict[str, Any]):
    """
    Yield (path, value) tuples for registry settings across common shapes:
      - gpo["RegistrySettings"] : [{Key, ValueName, Data}, ...]
      - gpo["Settings"]["Registry"] : [{Key, ValueName, Data}, ...]  (some export styles)
    """
    # 1) Direct RegistrySettings
    for rs in gpo_obj.get("RegistrySettings", []) or []:
        key = (rs.get("Key") or "").strip()
        val_name = (rs.get("ValueName") or "").strip()
        data = rs.get("Data")
        if key or val_name:
            yield (f"{key}\\{val_name}".strip("\\"), data)

    # 2) Nested under Settings.Registry
    settings = gpo_obj.get("Settings") or {}
    for rs in (settings.get("Registry") or []):
        key = (rs.get("Key") or "").strip()
        val_name = (rs.get("ValueName") or "").strip()
        data = rs.get("Data")
        if key or val_name:
            yield (f"{key}\\{val_name}".strip("\\"), data)

def _eval_setting_for_gpos(gpos: List[Dict[str, Any]], reg_path: str, secure_value: Any, fail_if_equal: bool):
    """
    Search all registry entries; classify:
      - secure_value is None -> PASS if any value present at that path (presence)
      - fail_if_equal=True  -> PASS if value == secure_value, else FAIL
      - fail_if_equal=False -> FAIL if value == secure_value, else PASS
    If no matching path seen across all GPOs -> FAIL and mark as unknown=True (needs more data).
    """
    target = (reg_path or "").lower()
    matched_any = False
    findings: List[Dict[str, str]] = []

    for g in gpos:
        gname = prop(g, "name", "<GPO>")
        for path, value in _iter_registry_items(g):
            if target in (path or "").lower():
                matched_any = True
                if secure_value is None:
                    # presence check
                    if value is not None and value != "":
                        return ("PASS", [], False)
                    findings.append({"Object": gname, "Detail": f"Missing value at {reg_path}"})
                else:
                    if fail_if_equal:
                        if value == secure_value:
                            return ("PASS", [], False)
                        findings.append({"Object": gname, "Detail": f"{reg_path}={value} (wanted {secure_value})"})
                    else:
                        if value == secure_value:
                            return ("FAIL", [{"Object": gname, "Detail": f"{reg_path}={value} (disallowed)"}], False)
                        else:
                            return ("PASS", [], False)

    if not matched_any:
        return ("FAIL", [{"Object": "N/A", "Detail": f"{reg_path} not found in GPOs"}], True)

    # matched but still not satisfied (e.g., presence check not met or value different)
    return ("FAIL", findings or [{"Object": "N/A", "Detail": f"{reg_path} mismatch"}], False)

# ========= Public API =========
def run_category10(input_dir: str | Path | None) -> Tuple[str, Dict[str, Any]]:
    """
    Category 10: GPO & Security Settings
    - Auto-resolves input_dir to .../Objects/Domain Data (with fallbacks)
    - Looks for registry settings in multiple export shapes
    Returns (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)
    gpos = _load_json_list(base / GPO_FILE)

    results: List[Dict[str, Any]] = []
    failed_by_sev = {"High": [], "Medium": [], "Low": []}
    unknown_items: List[Dict[str, Any]] = []

    for key, meta in CHECK_META.items():
        reg_path, secure_value, fail_if_equal = REGISTRY_MAP.get(key, (None, None, True))
        status, details, is_unknown = _eval_setting_for_gpos(gpos, reg_path, secure_value, fail_if_equal)

        rec = {
            "key": key, "title": meta["title"], "severity": meta["severity"],
            "score": meta["score"], "status": status, "fail_items": len(details), "details": details
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)
    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")

    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    # --- Build text report ---
    lines: List[str] = []
    lines.append("=== Category 10: GPO & Security Settings (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 10 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    for sev in ["High", "Medium", "Low"]:
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    lines.append("Non-passing (UNKNOWN) checks (counted separately):")
    for r in unknown_items:
        lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> additional data required")

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


# ========= CLI test =========
if __name__ == "__main__":
    text, summary = run_category10(None)  # auto-locate Domain Data
    print(text)
    print(summary)
