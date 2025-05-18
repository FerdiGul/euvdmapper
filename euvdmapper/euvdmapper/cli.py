import argparse
import asyncio
import csv
import json
import os
import shutil
import textwrap

from euvdmapper.euvd_alert import run_alert_mode

from euvdmapper.fetch_api import (
    fetch_euvd_entries,
    lookup_cve,
    lookup_euvd,
    fetch_exploited_vulnerabilities
)


def fit_ascii_to_terminal(art_text):
    term_width = shutil.get_terminal_size((80, 20)).columns
    fitted_lines = []
    for line in art_text.splitlines():
        if len(line) > term_width:
            fitted_lines.append(line[:term_width])
        else:
            fitted_lines.append(line)
    return "\n".join(fitted_lines)


def flatten_entry(entry):
    return {
        "EUVD_ID": entry.get("id", ""),
        "Alt_IDs": entry.get("aliases", "").replace("\n", ", "),
        "Exploitation": entry.get("exploitation", "Not available"),
        "CVSS": f'v{entry.get("baseScoreVersion", "")}: {entry.get("baseScore", "")}' if entry.get("baseScore") else "",
        "EPSS": entry.get("epss", ""),
        "Product": ", ".join([p["product"]["name"] for p in entry.get("enisaIdProduct", []) if "product" in p]),
        "Vendor": ", ".join([v["vendor"]["name"] for v in entry.get("enisaIdVendor", []) if "vendor" in v]),
        "Changed": entry.get("dateUpdated", ""),
        "Summary": entry.get("description", ""),
        "Version": ", ".join([p.get("product_version", "") for p in entry.get("enisaIdProduct", []) if "product_version" in p]),
        "Published": entry.get("datePublished", ""),
        "Updated": entry.get("dateUpdated", ""),
        "References": entry.get("references", "").replace("\n", ", ")
    }


def generate_html_report(data, output_file):
    """
    Generates an HTML report.

    Args:
        data (list): list of vulnerability entries.
        output_file (str): The path to the output HTML file.
    """
    html = """
    <html>
    <head>
        <meta charset=\"UTF-8\">
        <title>EUVD Vulnerability Report</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            h1 { font-size: 24px; }
            input, select, button {
                margin: 5px;
                padding: 8px;
                font-size: 14px;
            }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
            th { background-color: #f2f2f2; }
            td { font-size: 12px; }
            .low-risk { background-color: #d4edda; }
            .medium-risk { background-color: #fff3cd; }
            .high-risk { background-color: #ffe5b4; }
            .critical-risk { background-color: #f8d7da; }
        </style>
        <script>
            function searchTable() {
                let input = document.getElementById(\"searchInput\").value.toLowerCase();
                filterTable(input);
            }
            function filterTable(filterText = \"\") {
                let vendor = document.getElementById(\"vendorFilter\").value.toLowerCase();
                let product = document.getElementById(\"productFilter\").value.toLowerCase();
                let cvssRange = document.getElementById(\"cvssFilter\").value;
                let rows = document.querySelectorAll(\"table tbody tr\");
                rows.forEach(function(row) {
                    let text = row.textContent.toLowerCase();
                    let vendorText = row.cells[6].textContent.toLowerCase();
                    let productText = row.cells[5].textContent.toLowerCase();
                    let cvssScore = parseFloat(row.cells[3].textContent.split(\":\").pop()) || 0;
                    let cvssMatch = (
                        (cvssRange === \"all\") ||
                        (cvssRange === \"critical\" && cvssScore >= 9.0) ||
                        (cvssRange === \"high\" && cvssScore >= 8.0 && cvssScore < 9.0) ||
                        (cvssRange === \"medium\" && cvssScore >= 5.0 && cvssScore < 8.0) ||
                        (cvssRange === \"low\" && cvssScore < 5.0)
                    );
                    let match = text.includes(filterText) &&
                                 vendorText.includes(vendor) &&
                                 productText.includes(product) &&
                                 cvssMatch;
                    row.style.display = match ? \"\": \"none\";
                });
            }
            function exportPDF() {
                window.print();
            }
        </script>
    </head>
    <body>
        <h1>EUVD Vulnerability Report</h1>
        <input type=\"text\" id=\"searchInput\" onkeyup=\"searchTable()\" placeholder=\"Search in report...\">
        <select id=\"vendorFilter\" onchange=\"filterTable()\">
            <option value=\"\">Filter by Vendor</option>
        </select>
        <select id=\"productFilter\" onchange=\"filterTable()\">
            <option value=\"\">Filter by Product</option>
        </select>
        <select id=\"cvssFilter\" onchange=\"filterTable()\">
            <option value=\"all\">All CVSS</option>
            <option value=\"critical\">Critical (9.0+)</option>
            <option value=\"high\">High (8.0 - 8.9)</option>
            <option value=\"medium\">Medium (5.0 - 7.9)</option>
            <option value=\"low\">Low (< 5.0)</option>
        </select>
        <button onclick=\"exportPDF()\">Export PDF</button>
        <table>
            <thead>
                <tr>
                    <th>EUVD_ID</th><th>Alt_IDs</th><th>Exploitation</th><th>CVSS</th><th>EPSS</th><th>Product</th>
                    <th>Vendor</th><th>Changed</th><th>Summary</th><th>Version</th>
                    <th>Published</th><th>Updated</th><th>References</th>
                </tr>
            </thead>
            <tbody>
    """
    vendor_set = set()
    product_set = set()
    for entry in data:
        euvd_id = entry.get("id", "")
        alt_ids = entry.get("aliases", "").replace("\n", ", ")
        exploitation = entry.get("exploitation", "Not available")
        cvss_score = entry.get("baseScore")
        epss = entry.get("epss", "")
        cvss = f'v{entry.get("baseScoreVersion", "")}: {cvss_score}' if cvss_score else ""
        summary = entry.get("description", "")
        published = entry.get("datePublished", "")
        updated = entry.get("dateUpdated", "")
        references = entry.get("references", "").replace("\n", ", ")
        products = ", ".join([p["product"]["name"] for p in entry.get("enisaIdProduct", []) if "product" in p])
        versions = ", ".join([p.get("product_version", "") for p in entry.get("enisaIdProduct", []) if "product_version" in p])
        vendors = ", ".join([v["vendor"]["name"] for v in entry.get("enisaIdVendor", []) if "vendor" in v])
        vendor_set.update(vendors.split(", "))
        product_set.update(products.split(", "))
        row_class = ""
        if cvss_score is not None:
            try:
                score = float(cvss_score)
                if score == 0.0:
                    row_class = ""
                elif 0.1 <= score <= 3.9:
                    row_class = "low-risk"
                elif 4.0 <= score <= 6.9:
                    row_class = "medium-risk"
                elif 7.0 <= score <= 8.9:
                    row_class = "high-risk"
                elif 9.0 <= score <= 10.0:
                    row_class = "critical-risk"
            except ValueError:
                pass
        html += f"""
        <tr class="{row_class}">
            <td>{euvd_id}</td>
            <td>{alt_ids}</td>
            <td>{exploitation}</td>
            <td>{cvss}</td>
            <td>{epss}</td>
            <td>{products}</td>
            <td>{vendors}</td>
            <td>{updated}</td>
            <td>{summary}</td>
            <td>{versions}</td>
            <td>{published}</td>
            <td>{updated}</td>
            <td>{references}</td>
        </tr>
        """
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
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    MIN_WIDTH_FOR_ASCII = 72
    term_width = shutil.get_terminal_size((80, 20)).columns
    ascii_description = "\t@Developed by Ferdi Gül | @Github: /FerdiGul\n"
    ascii_art = r"""
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ~  _____ _   ___     ______                              ~
    ~ | ____| | | \ \   / /  _ \                             ~
    ~ |  _| | | | |\ \ / /| | | |                            ~
    ~ | |___| |_| | \ V / | |_| |                            ~
    ~ |_____|\___/   \_/  |____/                             ~
    ~  __  __                                     _   ____   ~
    ~ |  \/  | __ _ _ __  _ __   ___ _ __  __   _/ | |___ \  ~
    ~ | |\/| |/ _` | '_ \| '_ \ / _ \ '__| \ \ / / |   __) | ~
    ~ | |  | | (_| | |_) | |_) |  __/ |     \ V /| |_ / __/  ~
    ~ |_|  |_|\__,_| .__/| .__/ \___|_|      \_/ |_(_)_____| ~
    ~              |_|   |_|                                 ~
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """
    
    if term_width >= MIN_WIDTH_FOR_ASCII:
        print(ascii_art)
        print(ascii_description)
    else:
        print("EUVD Mapper - ENISA EUVD Data Retriever and Formatter")
        print(ascii_description)

    epilog_text = textwrap.dedent("""
        Examples:
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
              Uses a YAML watchlist (vendor + product pairs) to retrieve recent vulnerabilities and generates alert reports (CSV + HTML).
    """)

    parser = argparse.ArgumentParser(
        prog="euvdmapper",
        description="",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--keyword", help="Search keyword (text param)")
    parser.add_argument("--vendor", help="Filter by vendor (exact match)")
    parser.add_argument("--product", help="Filter by product (exact match)")
    parser.add_argument("--output", help="Output file: .json / .csv / .html")
    parser.add_argument("--lookup-cve", help="Get details by CVE ID")
    parser.add_argument("--lookup-euvd", help="Get details by EUVD ID")
    parser.add_argument("--max-entries", type=int, help="Max number of entries to fetch")
    parser.add_argument("--show-exploited", action="store_true", help="Fetch latest exploited vulnerabilities")
    parser.add_argument("--input", type=str, help="YAML watchlist file (each entry must include vendor and product)")
    parser.add_argument("--alerts", action="store_true", help="Trigger alert mode using the YAML watchlist")


    args = parser.parse_args()
    
    if bool(args.input) ^ bool(args.alerts):
        parser.error("Both --input and --alerts must be used together.")
    elif args.input and args.alerts:
        asyncio.run(run_alert_mode(args.input))
        return


    output_dir = "output"

    if args.lookup_cve:
        result = asyncio.run(lookup_cve(args.lookup_cve))
        print(json.dumps(result, indent=2))
        return

    if args.lookup_euvd:
        result = asyncio.run(lookup_euvd(args.lookup_euvd))
        print(json.dumps(result, indent=2))
        return

    if args.show_exploited:
        entries = asyncio.run(fetch_exploited_vulnerabilities())
    else:
        if not (args.keyword or args.vendor or args.product):
            print("Please provide at least one of --keyword, --vendor, or --product")
            return
        entries = asyncio.run(fetch_euvd_entries(
            keyword=args.keyword,
            vendor=args.vendor,
            product=args.product,
            max_entries=args.max_entries
        ))




    if not entries:
        print("[!] No results found.")
        return

    if args.output:
        output_file = os.path.join(output_dir, os.path.basename(args.output))
        os.makedirs(output_dir, exist_ok=True)

        if args.output.endswith(".json"):
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)

        elif args.output.endswith(".csv"):
            flattened = [flatten_entry(e) for e in entries]
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
                writer.writeheader()
                for row in flattened:
                    writer.writerow(row)

        elif args.output.endswith(".html"):
            generate_html_report(entries, output_file)
            print(f"[✓] HTML report saved as: {output_file}")
    else:
        print(json.dumps(entries, indent=2))


if __name__ == "__main__":
    main()

