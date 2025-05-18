# EUVD Mapper

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)

> ⚙️ ENISA EUVD Data Retriever and Formatter  
> Fetch, filter, and format data from ENISA’s Exploited Vulnerabilities Database (EUVD) with ease.

---

## ✨ Features

- 🔍 **Flexible Search**: Query vulnerabilities by keyword, vendor, product, or any combination
- 📤 **Multiple Export Formats**: Output results as `.json`, `.csv`, or interactive `.html` reports
- 🧠 **Smart HTML Reporting**:
  - CVSS-based risk coloring (Low/Medium/High/Critical)
  - Filter by vendor, product, or CVSS score
  - In-browser search and printable layout
- 🔎 **Lookup Utilities**:
  - Search by CVE ID or EUVD ID
  - Get alias mappings and extended metadata
- ⚠️ **Live Threat Feed**:
  - Fetch latest exploited vulnerabilities using ENISA’s public API
- 🖥️ **Responsive Terminal Experience**:
  - ASCII art displayed conditionally based on terminal width
  - Clean fallback view for narrow terminals
  
## 📋 YAML Watchlist Format (for Alert Mode)

To use the `--input <file>.yaml --alerts` feature, your YAML file **must** define both `vendor` and `product` fields for each entry.

### Example watchlist.yaml:

```yaml
watchlist:
  - vendor: Microsoft
    product: Windows 10
  - vendor: Fortinet
    product: FortiOS
  - vendor: Cisco
    product: IOS

---

## 📦 Installation

Install via `pip`:

```bash
pip install .
```

Or install from source:

```bash
git clone https://github.com/FerdiGul/euvdmapper.git
cd euvdmapper
pip install .
```

---

## 🚀 Usage

You can run the CLI tool via terminal:

```bash
euvdmapper --help
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

euvdmapper --lookup-cve CVE-2024-1234 --output cve_details.csv
    Looks up by CVE ID and exports to CSV.

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

> _(Replace this with a screenshot of your actual HTML report if available)_

![report-preview](docs/preview.png)

---

## 🙋‍♂️ Author

**Developed by**: Ferdi Gül  
📧 Email: [0xfrd1gul@gmail.com](mailto:0xfrd1gul@gmail.com)  
🔗 LinkedIn: [linkedin.com/in/ferdigul](https://linkedin.com/in/ferdigul)  
💻 GitHub: [github.com/FerdiGul](https://github.com/FerdiGul)

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).
