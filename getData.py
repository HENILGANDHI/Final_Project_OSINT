#CyberSecurityTechnologyClass
#Puya_Henil_Kanil
#November2024
import requests

def fetch_vulnerabilities(api_url, rows_to_fetch=200, results_per_page=100):
    """
    Fetches vulnerabilities from the NVD API.

    Parameters:
        api_url (str): The base URL for the NVD API.
        rows_to_fetch (int): The total number of vulnerabilities to fetch.
        results_per_page (int): Number of vulnerabilities to fetch per request.

    Returns:
        list: A list of vulnerabilities.
    """
    vulnerabilities = []
    start_index = 0

    while len(vulnerabilities) < rows_to_fetch:
        response = requests.get(
            api_url,
            params={
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
        )
        if response.status_code == 200:
            data = response.json()
            vulnerabilities.extend(data.get("vulnerabilities", []))
            start_index += results_per_page
        else:
            print(f"Error fetching data: {response.status_code}")
            break

        if len(data.get("vulnerabilities", [])) < results_per_page:
            break  # Stop if fewer results are returned than requested

    return vulnerabilities[:rows_to_fetch]

# Base URL for the NVD CVE API
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fetch 200 vulnerabilities
vulnerabilities = fetch_vulnerabilities(API_URL, rows_to_fetch=200)

# Display the fetched vulnerabilities (IDs and descriptions for demonstration)
for vuln in vulnerabilities:
    cve_id = vuln.get("cve", {}).get("id", "N/A")
    description = vuln.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description available")
    print(f"CVE ID: {cve_id}\nDescription: {description}\n")
