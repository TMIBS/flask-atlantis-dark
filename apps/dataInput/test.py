import json
import requests
import time
import nvdlib

def get_cve_details(cve_id):
    api_key = "5ac41e98-9e70-488e-a29e-7bed29ddfbca"
    try:
        response = nvdlib.searchCVE(cveId=cve_id, key=api_key, delay=0.61)
        if not response:
            print(f"No data found for {cve_id}")
            return None

        cve_item = response[0]  # Assuming the first item in the response is the relevant CVE

        # Extract the CWE ID if available
        cwe_id = None
        if hasattr(cve_item, 'cwe'):
            cwe_id = cve_item.cwe[0].value
        
        # Load the CWE names data
        with open('apps/static/assets/data/cwe_names.json') as f:
            cwe_data = json.load(f)
        
        # Search for the CWE name
        cwe_name = next((item['CWE_NAME'] for item in cwe_data if item['CWE_ID'] == cwe_id), None)
        cve_details = {
            "CVE_ID": cve_id,
            "description": cve_item.descriptions[0].value if hasattr(cve_item, 'descriptions') and cve_item.descriptions else None,
            "CWE_ID": cwe_id,
            "CWE_NAME": cwe_name,
            "references": [ref.url for ref in cve_item.references] if hasattr(cve_item, 'references') and cve_item.references else []
        }
        return cve_details


    except (KeyError, IndexError) as e:
        print(f"Error accessing data for {cve_id}: {e}")
        return None
    
def load_cve_ids(siteid):
    file_path = f"apps/static/assets/data/all_cves_site_{siteid}.json"
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data, file_path

def save_cve_details(cve_details, siteid):
    output_file_path = f"apps/static/assets/data/all_cves_details_site_{siteid}.json"
    with open(output_file_path, 'w') as file:
        json.dump(cve_details, file, indent=4)
        
def get_cve_details_for_site(siteid):
    # Load the CVE IDs from the specified JSON file
    cve_ids, file_path = load_cve_ids(siteid)
    all_cve_details = []
    for cve_id in cve_ids:
        cve_details = get_cve_details(cve_id)
        time.sleep(0.6) # to avoid getting 50 request per 30 seconds (see https://stackoverflow.com/questions/72549122/rate-limits-for-nist-api)
        if cve_details is not None:
            all_cve_details.append(cve_details)
    save_cve_details(all_cve_details, siteid)
    
if __name__ == "__main__":
    get_cve_details_for_site(8)