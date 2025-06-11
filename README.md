# Nessus Vulnerability Tracker 📊

This project processes `.nessus` files exported from Tenable Nessus, converts them into structured Excel reports, and compares historical scan results to identify:

- ✅ Newly discovered vulnerabilities  
- 🛠️ Resolved vulnerabilities  

It helps with vulnerability management and tracking over time — no external tools or API keys required.

---

## 🚀 Features

- Convert `.nessus` XML files to clean, structured Excel reports  
- Uses a custom Excel template with the following columns:

  ```
  Risk | Host | Service | Protocol | Port | Name | CVE | Exploitable | TESPİT TARİHİ | STATUS | Description | Solution
  ```

- Compare two Excel reports and output differences:
  - `Durum = Yeni` → New vulnerabilities  
  - `Durum = Çözülmüş` → Resolved vulnerabilities  

- Fully offline and CLI-based

---

## 📦 Requirements

Install Python dependencies:

```bash
pip install pandas openpyxl lxml
```

---

## 🛠️ Usage

### 1. Convert `.nessus` file to Excel

```bash
python3 nessus-to-excel.py eski.nessus rapor_eski.xlsx
python3 nessus-to-excel.py yeni.nessus rapor_yeni.xlsx
```

### 2. Compare two Excel files

Ensure `compare_reports.py` contains the correct filenames:

```python
eski_dosya = "rapor_eski.xlsx"
yeni_dosya = "rapor_yeni.xlsx"
```

Then run:

```bash
python3 compare_reports.py
```

This generates a new file:  
📄 `karsilastirma_sonuclari.xlsx` — with a new column: `Durum`

---

## 📁 Project Structure

```
nessus-vuln-tracker/
├── nessus-to-excel.py          # Parses .nessus files into Excel
├── compare_reports.py          # Compares two Excel reports
├── README.md                   # Project documentation
├── .gitignore                  # Ignores .nessus and .xlsx files
```

---

## 🔐 Notes

- `.nessus` and `.xlsx` files are excluded via `.gitignore`  
- No sensitive data is committed to the repository  
- Easily extendable for GUI (Streamlit), dashboards, or email alerting

---
