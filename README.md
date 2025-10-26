# 🔐 TrustScope — Make AD Risk Measurable, Explainable & Actionable

> **One-liner:** Research-led platform that turns Active Directory (AD) state into **transparent 0–100 risk scores**, **attack-path insights**, and **prescriptive fixes**—useful for exec dashboards and engineer runbooks. ✨

![Status](https://img.shields.io/badge/status-research-blue)
![Focus](https://img.shields.io/badge/focus-Active%20Directory-4B8BBE)


---

## 🧠 How It Works
- **Collect (read-only):** Users, groups, computers, OUs/GPOs, trusts via PowerShell / LDAP / WinRM.
- **Normalize:** Validate into JSON/CSV 📄 with checksums/timestamps.
- **Score:** Rule engine with **Likelihood × Impact × Weight** → category scores → **domain KPI (0–100)** 📊
- **Traceable:** Every rule cites **CIS Benchmarks**, **Microsoft hardening**, and **MITRE ATT&CK** for audit-ready provenance. 🧾

---

## 🕸️ Graph Intelligence (Beyond Checklists)
- **Identity & trust graph:** Nodes = Users, Groups, Computers, DCs, OUs, GPOs, Trusts.  
  Edges = MemberOf, ACL rights (GenericAll/WriteDACL), Delegation, GPO links, Sessions, LocalAdmin/RDP.
- **Find paths:** Shortest escalation routes to **Tier-0** (DCs, DA/EA, PKI CA) and **choke points** where one fix kills many paths. 🧩
- **What-if lab:** Rotate **KRBTGT**, remove **unconstrained delegation**, shrink **privileged groups**, disable **legacy auth** → see **Δscore** and paths removed. 🧪

---

## 📈 Outputs For Everyone
- **Leaders:** Overall risk score, category radar, severity breakdown, trends. 🚦  
- **Engineers:** Full rule ledger with deep links (DNs, GPO paths, attributes) + prescriptive playbooks. 🛠️  
- **Lab highlight:** Detected **85.8% (High)** posture concentrated in privileged identities, DC health, and trust management; **top-5 fixes** significantly reduced open paths to Tier-0. 🚀

---

## 🧰 What’s In The Box
- **Schemas** • **Collectors** • **Scoring & Graph tooling** • **Dashboards**  
- **Exports:** JSON / CSV / PDF / API for audits and integrations. 🔌

