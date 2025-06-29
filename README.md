# EUVD Mapper v1.7

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/euvdmapper)
![PyPI Downloads](https://static.pepy.tech/badge/euvdmapper)
> ⚙️ ENISA EUVD Data Retriever and Formatter  
> Fetch, filter, and format data from ENISA’s Exploited Vulnerabilities Database (EUVD) with ease.

<img width="484" alt="banner" src="https://github.com/user-attachments/assets/9cbaba4c-cb21-4c78-a55c-5e8e26fc1af0" />


---

✨ Features

🔄 **ENISA API Change** – /vulnerability → /search - NEW
- The old /vulnerability endpoint has been replaced by /search. All lookup functions (e.g. lookup_cve) now query /search under the hood to stay in sync with ENISA’s updated API.

📂 **Customizable Output Directory (CWD Saving)** - NEW
- Outputs are saved relative to your current working directory (or to the path you specify). No more hard-coded output/ folder—just pass --output filename.ext (or include subdirs) and we’ll create them if needed.

🔄 **New Lookup Flags**  - NEW
 '--last`  Show the latest 8 EUVD entries  
 `--critical`  Show the latest 8 critical vulnerabilities  
 `--enisa-id`  Lookup by ENISA internal ID (EUVD-YYYY-XXXX)  
 `--advisory-id`  Lookup full advisory details by its slug  

🚫 **No-Banner Mode**  - NEW
- `--no-banner`  Suppress the ASCII art on terminals (works with `-h` too!)

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

euvdmapper --keyword fortinet --no-banner | jq .
    # raw JSON output (no banner)

euvdmapper --last --output last.json
    # fetches last 8 entries (API cap: max 8)

euvdmapper --critical --output critical.csv
    # fetches last 8 critical entries (API cap: max 8)

euvdmapper --enisa-id EUVD-2025-1234
    # lookup by ENISA internal ID

euvdmapper --advisory-id cisco-sa-20210315-abcd
    # fetch full advisory metadata

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


https://github.com/user-attachments/assets/5a2b1196-dfaa-49f9-9b52-8bede5bc5804


---

## 🙋‍♂️ Author

**Developed by**: Ferdi Gül  
📧 Email: [0xfrd1gul@gmail.com](mailto:0xfrd1gul@gmail.com)  
🔗 LinkedIn: [linkedin.com/in/ferdigul](https://linkedin.com/in/ferdigul)  
💻 GitHub: [github.com/FerdiGul](https://github.com/FerdiGul)

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).
