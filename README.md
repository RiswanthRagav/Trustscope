# TrustScope
A transparent, graph-powered AD risk framework with explainable scoring and path-aware remediation—built for fast, auditable identity hardening.

## TrustScope: Open, Explainable AD Risk Scoring & Attack-Path Analytics
TrustScope is an end-to-end framework that turns Active Directory state into **0–100 risk KPIs**, **graph-derived escalation paths**, and **prescriptive fixes**. It combines a standards-aligned rule ledger (CIS, Microsoft, MITRE ATT&CK) with a trust graph to prioritize the few changes that collapse the most attack paths—**no black boxes**.

---

## 🚀 Key Features
- **Explainable Risk Scoring:** Transparent **L × I × W** rubric per rule; category weights; normalized **0–100** KPI.
- **Graph-Aware Prioritization:** Model users, groups, ACLs, delegation, trusts → find **shortest paths** to Tier-0 and **choke points** to fix first.
- **What-If Remediation Simulator:** Test KRBTGT rotation, removing unconstrained delegation, shrinking privileged groups, disabling legacy auth → see **Δscore** and **paths removed**.
- **Dual Views:** Executive radar/severity/trends for KPIs; engineer ledger with **evidence links** (DNs, GPO paths) and **step-by-step playbooks**.
- **Reproducible by Design:** Read-only collectors, versioned schemas, deterministic scoring, auditable rule provenance (CIS/Microsoft/ATT&CK).

---

## 🏗️ Architecture
**Collection → Ingestion → Rule Engine & Graph → Scoring → Presentation/Exports**

- **Collection:** PowerShell/LDAP/WinRM (Windows), Kerberos/NTLM scripts (Linux) — read-only.
- **Ingestion:** JSON/CSV validation, checksums, timestamps.
- **Rule Engine:** Standards-aligned checks with L/I/W and category weights.
- **Graph:** Nodes (Users, Groups, Computers, DCs, OUs, GPOs, Trusts); Edges (MemberOf, ACL rights, Delegation, GPO links, Sessions, LocalAdmin/RDP).
- **Presentation:** Dashboards, evidence drill-downs, reports; exports (**JSON/CSV/PDF/API**).

> _Diagram:_ `docs/figs/trustscope-architecture.svg`

---

## 🛠️ Technology Stack
- **Collectors:** PowerShell, Bash, LDAP, WinRM  
- **Scoring/Graph:** Python, NetworkX/graph DB (optional), Pandas  
- **UI:** Streamlit or FastAPI + React (optional)  
- **Standards:** CIS Benchmarks, Microsoft AD hardening, MITRE ATT&CK  
- **Ops:** Docker (optional), Make, pre-commit, GitHub Actions (CI)

---

## 📊 Example Results (Lab Validation)
| Scenario / Metric | Result |
|---|---|
| Overall Domain Risk (baseline) | **85.8% (High)** |
| Critical Misconfig Density | **40.4% of failures = High** |
| Top Weak Areas | Privileged Identities, DC Health, Privilege/Trust Mgmt |
| What-If (Top-5 Fixes) | Open paths to Tier-0 ↓ **61%** |
| Projected KPI After Fixes | **63.4** |

---

## 🔒 Security & Ethics
- Read-only data collection; **no secrets harvested**.  
- Exports can be **anonymized & encrypted**.  
- Use in lab or with **written authorization** only.

---

