# Nessus Vulnerability Tracker 📊

This project processes `.nessus` files exported from Tenable Nessus, converts them into structured Excel reports, and compares historical scans to identify:

- ✅ New vulnerabilities
- 🛠️ Resolved vulnerabilities

## 🚀 Features

- Converts `.nessus` XML reports to Excel (`.xlsx`)
- Follows a custom template with columns like Risk, Host, Port, CVE, etc.
- Compares two Excel reports and outputs differences (new vs resolved)
- Pure Python (no API key required)

## 📂 Output Excel Template

| Risk | Host | Service | Protocol | Port | Name | CVE | Exploitable | TESPİT TARİHİ | STATUS | Description | Solution |

## 🛠️ Requirements

```bash
pip install pandas openpyxl lxml
