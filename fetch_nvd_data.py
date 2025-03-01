import requests
import pandas as pd
import time

# Set number of CVEs to fetch
total_results = 90000  # Adjust as needed
batch_size = 1000  # NVD API max is 2,000 per request

# API base URL
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# List to store all CVEs
all_cves = []

# Fetch CVEs in batches
for start_index in range(0, total_results, batch_size):
    params = {"resultsPerPage": batch_size, "startIndex": start_index}
    print(f"Fetching {batch_size} CVEs starting from index {start_index}...")

    response = requests.get(api_url, params=params)
    if response.status_code != 200:
        print(f"❌ API request failed at index {start_index}. Skipping...")
        continue

    data = response.json()

    # Extract relevant fields
    for cve in data.get("vulnerabilities", []):
        cve_id = cve["cve"]["id"]
        descriptions = cve["cve"].get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        # Extract CVSS Score
        cvss_v3 = cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", None)
        cvss_v2 = cve["cve"].get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", None)
        cvss_score = cvss_v3 if cvss_v3 else cvss_v2  # Use CVSS v3 if available, else fallback to v2

        # Extract CWE (Common Weakness Enumeration)
        cwe_data = cve["cve"].get("weaknesses", [])
        if cwe_data and "description" in cwe_data[0]:
            cwe = cwe_data[0]["description"][0].get("value", "Unknown")
        else:
            cwe = "Unknown"

        # Store the extracted CVE data
        all_cves.append([cve_id, description, cvss_score, cwe])

    print(f"✅ Successfully fetched {len(all_cves)} CVEs so far.")
    
    # Respect API rate limits
    time.sleep(2)

# Convert to DataFrame
df_nvd = pd.DataFrame(all_cves, columns=["CVE_ID", "Description", "CVSS_Score", "CWE"])

# Save to CSV
df_nvd.to_csv("nvd_vulnerability_data_large.csv", index=False, encoding="utf-8-sig")
print(f"✅ Data saved as `nvd_vulnerability_data_large.csv` with {len(df_nvd)} CVEs.")
