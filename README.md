# EUVD Mapper v1.4

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/euvdmapper)
[![Downloads](https://img.shields.io/pypi/dm/euvdmapper)](https://pypi.org/project/euvdmapper/)


> ⚙️ ENISA EUVD Data Retriever and Formatter  
> Fetch, filter, and format data from ENISA’s Exploited Vulnerabilities Database (EUVD) with ease.

<img width="512" alt="cover" src="https://github.com/user-attachments/assets/ffdeadf8-e931-4314-8b59-2089f36ab04b" />

---

✨ Features

🔍 **Flexible Search**  
Query vulnerabilities by keyword, vendor, product, or any combination.

📤 **Multiple Export Formats**  
Output results as `.json`, `.csv`, or interactive `.html` reports.

🧠 **Smart HTML Reporting**  
- CVSS-based risk coloring (Low / Medium / High / Critical)  
- Filter by vendor, product, or CVSS score  
- In-browser search and the ability to export reports in PDF format.
  
🔎 **Lookup Utilities**  
- Search by CVE ID or EUVD ID  
- Get alias mappings and extended metadata

⚠️ **Live Threat Feed**  
Fetch latest exploited vulnerabilities using ENISA’s public API.

📌 **Customized Watchlist Alerts**  
- YAML-powered alerting system based on specific vendor/product pairs  
- Generates filtered `.csv` and `.html` reports  
- Automatically highlights high/critical vulnerabilities for watched assets

🖥️ **Responsive Terminal Experience**  
- ASCII art banner shown conditionally based on terminal width  
- Clean fallback mode for small terminal displays

---
### 📋 YAML Watchlist Format (for Alert Mode)

To use the `--input <file>.yaml --alerts` feature, your YAML file **must** define both `vendor` and `product` fields for each entry.

### Example `watchlist.yaml`:

```yaml
watchlist:
  - vendor: Microsoft
    product: Windows 10
  - vendor: Fortinet
    product: FortiOS
  - vendor: Cisco
    product: IOS
```
---

## 📦 Installation

** PYPI
You can install **euvdmapper** directly from [PyPI](https://pypi.org/project/euvdmapper/):

```bash
pip install euvdmapper


** Install from source:

```bash
git clone https://github.com/FerdiGul/euvdmapper.git
cd euvdmapper
pip install .

---

## 🚀 Usage

You can run the CLI tool via terminal:

```bash
euvdmapper -h
```

### 🔍 Examples

```bash
euvdmapper --keyword fortinet
    Searches for vulnerabilities by keyword and prints the results.

euvdmapper --keyword fortinet --output fortinet.csv
    Searches and exports results to CSV.

euvdmapper --keyword fortinet --output fortinet.html
    Generates an interactive HTML report.

euvdmapper --keyword google --output google.json
    Exports data in JSON format.

euvdmapper --lookup-cve CVE-2024-1234
    Looks up by CVE ID and prints to terminal.

euvdmapper --lookup-euvd EUVD-2024-5678
    Looks up by EUVD ID and prints to terminal.

euvdmapper --show-exploited --output exploited.html
    Displays the latest exploited vulnerabilities and generates an HTML report.

euvdmapper --show-exploited --output exploited.json
    Displays the latest exploited vulnerabilities and exports to JSON.

euvdmapper --vendor Fortinet --output fortinet.html
    Filters vulnerabilities by vendor and generates an HTML report.

euvdmapper --product FortiOS --output fortios.csv
    Filters vulnerabilities by product and exports to CSV.

euvdmapper --keyword firewall --vendor Fortinet
    Searches by keyword and filters by vendor.

euvdmapper --keyword firewall --vendor Fortinet --product FortiGate --output combo.json
    Full filter: keyword + vendor + product with export.

euvdmapper --input watchlist.yaml --alerts
    Loads a YAML-based custom vendor/product watchlist and generates interactive HTML + CSV
    reports with CVSS-based risk levels, alt IDs, and filterable UI.
```

---

## 📂 Output Formats

| Format   | Description                                |
|----------|--------------------------------------------|
| `.json`  | Machine-readable structured output          |
| `.csv`   | Spreadsheet-friendly tabular data           |
| `.html`  | Interactive report with filterable UI       |

> 🔔 HTML reports support browser search, color-coding by CVSS, and filter dropdowns.

---

## 📸 Preview

<img width="1458" alt="IMG2" src="https://github.com/user-attachments/assets/33526ca5-ae6d-4663-8ed2-adcaebdec16c" />
<img width="1445" alt="IMG1" src="https://github.com/user-attachments/assets/2f18cd03-bcbd-4cce-8a8c-12379da595ab" />


---

## 🙋‍♂️ Author

**Developed by**: Ferdi Gül  
📧 Email: [0xfrd1gul@gmail.com](mailto:0xfrd1gul@gmail.com)  
🔗 LinkedIn: [linkedin.com/in/ferdigul](https://linkedin.com/in/ferdigul)  
💻 GitHub: [github.com/FerdiGul](https://github.com/FerdiGul)

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).
