import asyncio
import os
import csv
import json
import yaml
from datetime import datetime
from euvdmapper.fetch_api import fetch_euvd_entries

# write directly into cwd
OUTPUT_DIR = "."
HTML_FILE  = "watchlist.html"
CSV_FILE   = "watchlist.csv"


def get_cvss_label(score):
    try:
        score = float(score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    except:
        return "Unknown"


def generate_watchlist_html(data):
    html = """<html>
<head>
    <meta charset="UTF-8">
    <title>Customized Latest Vulnerability Watchlist</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { font-size: 26px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; font-size: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .Critical { background-color: #f8d7da; }
        .High { background-color: #ffe5b4; }
        .Medium { background-color: #fff3cd; }
    </style>
    <script>
        function filterTable(filterText = "") {
            let vendor = document.getElementById("vendorFilter").value.toLowerCase();
            let product = document.getElementById("productFilter").value.toLowerCase();
            let label = document.getElementById("labelFilter").value.toLowerCase();
            let rows = document.querySelectorAll("table tbody tr");
            rows.forEach(function(row) {
                let text = row.textContent.toLowerCase();
                let vendorText = row.cells[5].textContent.toLowerCase();
                let productText = row.cells[4].textContent.toLowerCase();
                let labelText = row.cells[3].textContent.toLowerCase();
                let match = text.includes(filterText.toLowerCase()) &&
                            vendorText.includes(vendor) &&
                            productText.includes(product) &&
                            labelText.includes(label);
                row.style.display = match ? "" : "none";
            });
        }
    </script>
</head>
<body>
    <h1>Customized Latest Product/Vendor Vulnerability Alert System</h1>
    <input type="text" id="searchInput" onkeyup="filterTable(this.value)" placeholder="Search in report...">
    <select id="vendorFilter" onchange="filterTable()">
        <option value="">Filter by Vendor</option>
    </select>
    <select id="productFilter" onchange="filterTable()">
        <option value="">Filter by Product</option>
    </select>
    <select id="labelFilter" onchange="filterTable()">
        <option value="">Filter by Risk Level</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
    </select>
    <table>
        <thead>
            <tr>
                <th>EUVD_ID</th><th>Alt_IDs</th><th>CVSS</th><th>Risk Level</th><th>Product</th><th>Vendor</th><th>Summary</th><th>Updated</th>
            </tr>
        </thead>
        <tbody>
"""
    vendor_set = set()
    product_set = set()

    for entry in data:
        euvd_id = entry.get("id", "")
        alt_ids = entry.get("aliases", "").replace("\n", ", ")
        cvss_score = entry.get("baseScore", "")
        label = get_cvss_label(cvss_score)
        products = [p["product"]["name"] for p in entry.get("enisaIdProduct", []) if "product" in p]
        product_str = ", ".join(products)
        vendors = [v["vendor"]["name"] for v in entry.get("enisaIdVendor", []) if "vendor" in v]
        vendor_str = ", ".join(vendors)
        summary = entry.get("description", "").replace("<", "&lt;").replace(">", "&gt;")
        updated = entry.get("dateUpdated", "")
        vendor_set.update(vendors)
        product_set.update(products)
        html += f"<tr class='{label}'><td>{euvd_id}</td><td>{alt_ids}</td><td>{cvss_score}</td><td>{label}</td><td>{product_str}</td><td>{vendor_str}</td><td>{summary}</td><td>{updated}</td></tr>"

    html += """
        </tbody>
    </table>
    <script>
        let vendorFilter = document.getElementById("vendorFilter");
        let productFilter = document.getElementById("productFilter");
    """
    for vendor in sorted(vendor_set):
        html += f'vendorFilter.innerHTML += `<option value="{vendor}">{vendor}</option>`;\n'
    for product in sorted(product_set):
        html += f'productFilter.innerHTML += `<option value="{product}">{product}</option>`;\n'
    html += """
    </script>
</body>
</html>
"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)


def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["EUVD_ID", "Alt_IDs", "CVSS", "Risk Level", "Product", "Vendor", "Summary", "Updated"])
        for entry in data:
            euvd_id = entry.get("id", "")
            alt_ids = entry.get("aliases", "").replace("\n", ", ")
            cvss_score = entry.get("baseScore", "")
            label = get_cvss_label(cvss_score)
            product = ", ".join([p["product"]["name"] for p in entry.get("enisaIdProduct", []) if "product" in p])
            vendor = ", ".join([v["vendor"]["name"] for v in entry.get("enisaIdVendor", []) if "vendor" in v])
            summary = entry.get("description", "").replace("\n", " ")
            updated = entry.get("dateUpdated", "")
            writer.writerow([euvd_id, alt_ids, cvss_score, label, product, vendor, summary, updated])


async def run_alert_mode(yaml_path):
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Failed to load YAML file: {e}")
        return

    watchlist = config.get("watchlist", [])
    all_entries = []

    for item in watchlist:
        vendor = item.get("vendor")
        product_query = item.get("product", "").lower()
        if not vendor or not product_query:
            continue
        print(f"Fetching vulnerabilities for {vendor} and filtering product by: '{product_query}'...")
        results = await fetch_euvd_entries(vendor=vendor)
        filtered = []
        for entry in results:
            base = entry.get("baseScore")
            if base is None or (isinstance(base, str) and not base.replace(".", "").isdigit()):
                continue
            products = [p["product"]["name"].lower() for p in entry.get("enisaIdProduct", []) if "product" in p]
            if any(product_query in p for p in products):
                filtered.append(entry)
        all_entries.extend(filtered)

    all_entries.sort(key=lambda x: x.get("dateUpdated", ""), reverse=True)
    generate_watchlist_html(all_entries)
    save_csv(all_entries)
    print("[✓] Alert report generated as watchlist.html and watchlist.csv")
