import httpx
import asyncio

API_BASE = "https://euvdservices.enisa.europa.eu/api"

async def fetch_euvd_entries(keyword=None, vendor=None, product=None, max_entries=None):
    entries = []
    page_size = 100
    tasks = []

    async with httpx.AsyncClient() as client:
    
        try:
            url = f"{API_BASE}/vulnerabilities"
            params = {"page": 0, "size": page_size}
            if keyword:
                params["text"] = keyword
            if vendor:
                params["vendor"] = vendor
            if product:
                params["product"] = product

            response = await client.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            total_items = data.get("totalElements", 0)
            first_page_items = data.get("items", [])
            entries.extend(first_page_items)
        except Exception as e:
            print(f"[ERROR] Initial page fetch failed: {e}")
            return []

        
        total_pages = (total_items + page_size - 1) // page_size
        if max_entries:
            total_pages = min(total_pages, (max_entries + page_size - 1) // page_size)

      
        for page in range(1, total_pages):
            params_page = {"page": page, "size": page_size}
            if keyword:
                params_page["text"] = keyword
            if vendor:
                params_page["vendor"] = vendor
            if product:
                params_page["product"] = product
            tasks.append(fetch_page(client, params_page))

        pages = await asyncio.gather(*tasks)
        for items in pages:
            entries.extend(items)
            if max_entries and len(entries) >= max_entries:
                return entries[:max_entries]

    return entries


async def fetch_page(client, params):
    url = f"{API_BASE}/vulnerabilities"
    try:
        response = await client.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json().get("items", [])
    except Exception as e:
        print(f"[ERROR] Page fetch failed: {e}")
        return []


async def lookup_cve(cve_id: str):
    url = f"{API_BASE}/vulnerability"
    try:
        response = httpx.get(url, params={"id": cve_id}, timeout=30)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError:
        return None


async def lookup_euvd(euvd_id: str):
    url = f"{API_BASE}/enisaid"
    try:
        response = httpx.get(url, params={"id": euvd_id}, timeout=30)
        response.raise_for_status()
        data = response.json()

        # aliases: enisaIdVulnerability -> vulnerability.id
        aliases = set()
        for item in data.get("enisaIdVulnerability", []):
            vuln = item.get("vulnerability", {})
            vuln_id = vuln.get("id", "").strip()
            if vuln_id:
                aliases.add(vuln_id)

        # Add to main object
        data["aliases"] = ", ".join(sorted(aliases))

        # Delete unnecessary fields
        data.pop("enisaIdVulnerability", None)
        data.pop("enisaIdAdvisory", None)

        return data
    except httpx.HTTPStatusError:
        return None


async def fetch_exploited_vulnerabilities():
    url = f"{API_BASE}/exploitedvulnerabilities"
    try:
        response = httpx.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[ERROR] Could not fetch exploited vulnerabilities: {e}")
        return []

