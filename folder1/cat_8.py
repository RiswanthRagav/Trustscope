#!/usr/bin/env python3
import os, json
from typing import List, Dict, Any
from collections import Counter, defaultdict

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
COMPUTERS_FILE = "nexora.local_computers.json"

PRINT_MAX_DETAILS = 10
OS_MIN_FREE_PERCENT   = 15
NTDS_MIN_FREE_PERCENT = 15

# ========= Risk model (Category 8) =========
CHECK_META = {
    "os_partition_low":   {"title": "OS partition low space",   "severity": "Low", "score": 18},
    "ntds_partition_low": {"title": "NTDS partition low space", "severity": "Low", "score": 18},
}

# ========= helpers =========
def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return data if isinstance(data, list) else []

def prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

# ========= checks =========
def check_os_partition(computers):
    issues=[]
    for c in computers:
        dn=prop(c,"distinguishedname","").lower()
        if "ou=domain controllers" not in dn: 
            continue
        name=prop(c,"name","<DC>")
        free=prop(c,"os_partition_free_percent")
        if free is None:
            issues.append({"Object":name,"Detail":"OS free space unknown"})
        elif free<OS_MIN_FREE_PERCENT:
            issues.append({"Object":name,"Detail":f"OS free {free}% < {OS_MIN_FREE_PERCENT}%"})
    if not computers: return "UNKNOWN",[],True
    return ("FAIL",issues,False) if issues else ("PASS",[],False)

def check_ntds_partition(computers):
    issues=[]
    for c in computers:
        dn=prop(c,"distinguishedname","").lower()
        if "ou=domain controllers" not in dn: 
            continue
        name=prop(c,"name","<DC>")
        free=prop(c,"ntds_partition_free_percent")
        if free is None:
            issues.append({"Object":name,"Detail":"NTDS free space unknown"})
        elif free<NTDS_MIN_FREE_PERCENT:
            issues.append({"Object":name,"Detail":f"NTDS free {free}% < {NTDS_MIN_FREE_PERCENT}%"})
    if not computers: return "UNKNOWN",[],True
    return ("FAIL",issues,False) if issues else ("PASS",[],False)

# ========= run =========
def main():
    computers=load_json(os.path.join(INPUT_DIR,COMPUTERS_FILE))

    CHECKS=[
        ("os_partition_low",   lambda: check_os_partition(computers)),
        ("ntds_partition_low", lambda: check_ntds_partition(computers)),
    ]

    results=[]
    failed_by_sev={"High":[],"Medium":[],"Low":[]}

    for key,fn in CHECKS:
        status,details,is_unknown=fn()
        meta=CHECK_META[key]
        rec={
            "key":key,
            "title":meta["title"],
            "severity":meta["severity"],
            "score":meta["score"],
            "status":status,
            "unknown":is_unknown,
            "fail_items":len(details),
            "details":details
        }
        results.append(rec)
        if status=="FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    # ===== report =====
    total=len(results)
    failed_total=sum(1 for r in results if r["status"]=="FAIL")
    unknown_total=sum(1 for r in results if r.get("unknown"))
    by_sev_counts=Counter(r["severity"] for r in results if r["status"]=="FAIL")
    category_risk_total=sum(r["score"] for r in results if r["status"]=="FAIL")
    risk_by_severity=defaultdict(int)
    for r in results:
        if r["status"]=="FAIL":
            risk_by_severity[r["severity"]]+=r["score"]

    print("\n=== Category 8: System & Disk Health (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 8 Total Risk Score: {category_risk_total}")
    print(f"  - High risk points:   {risk_by_severity['High']}")
    print(f"  - Medium risk points: {risk_by_severity['Medium']}")
    print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    print("Failures by severity:")
    print(f"  High  : {by_sev_counts.get('High',0)}")
    print(f"  Medium: {by_sev_counts.get('Medium',0)}")
    print(f"  Low   : {by_sev_counts.get('Low',0)}\n")

    def print_failed_block(sev):
        items=failed_by_sev.get(sev,[])
        if not items: 
            print(f"{sev}: (none)"); return
        print(f"{sev}:")
        for r in items:
            print(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                print(f"      • {d['Object']} - {d['Detail']}")
            if r["fail_items"]>PRINT_MAX_DETAILS:
                print(f"      ... and {r['fail_items']-PRINT_MAX_DETAILS} more")
        print()

    print_failed_block("Low")

    print("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r.get("unknown"):
            print(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")
    print()

if __name__=="__main__":
    main()
