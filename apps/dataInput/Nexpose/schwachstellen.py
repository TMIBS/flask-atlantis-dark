import requests
from flask import Flask, render_template,jsonify, Blueprint
import json
import base64
import urllib3
from datetime import datetime, timedelta
from base64 import b64encode
import http.client
import os
import ssl
import sys
import time
import nvdlib


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

blueprint = Blueprint('schwachstellen', __name__)

# Configuration for the API
IVM_BASE_URL = 'https://nexpose.kdo.de:3780/api/3'
IVM_USER = input('Username:')
IVM_PASS = input('Password:')

#Helper see https://discuss.rapid7.com/t/insightvm-asset-search-automation/125
class InsightVmApi:
    def __init__(self, username, password, verify_ssl):
        # Craft basic authentication
        auth = f"{username}:{password}"
        auth = b64encode(auth.encode('ascii')).decode()

        self.base_resource = "/api/3"
        self.headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': f"Basic {auth}"
        }
        self.conn = http.client.HTTPSConnection('nexpose.kdo.de:3780')

        if verify_ssl == 'false':
            # Ignore certificate verification for self-signed certificate; NOT to be used in production
            self.conn._context=ssl._create_unverified_context()

    def asset_search(self, filters, match):
        body = {
            "filters": filters,
            "match": match,
        }
        page = 0
        size = 50000
        matched_assets = []

        while(True):
            self.conn.request("POST", f"{self.base_resource}/assets/search?page={page}&size={size}", json.dumps(body),
                              self.headers)
            resp = self.conn.getresponse()
            data = resp.read()
            resp_dict = json.loads(data.decode())

            matched_assets.extend(resp_dict["resources"])

            if resp_dict["page"]["totalPages"] > page + 1:
                page += 1
            else:
                break

        return matched_assets

#Login
def get_authentication_sources():
    url = f'{IVM_BASE_URL}/authentication_sources'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        return None
    else:
        print(f'Failed to retrieve authentication sources. Status code: {response.status_code}')
        print(response.text)

def check_login():
    url = 'https://nexpose.kdo.de:3780/vulnerability/listing.jsp'  # Replace with a valid endpoint to check login
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False, allow_redirects=False)
    if response.status_code == 200:
        return None
    else:
        print(f'Failed to retrieve check login. Status code: {response.status_code}')
        print(response.text)
        return None

#Site

def list_all_sites():
    url = f'{IVM_BASE_URL}/sites'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        sites = response.json()['resources']
        for site in sites:
            print(f"Site ID: {site['id']}, Site Name: {site['name']}")
    else:
        print(f'Failed to retrieve sites. Status code: {response.status_code}')

def get_assets_in_site(site_id):
    url = f'{IVM_BASE_URL}/sites/{site_id}/assets'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    
    if response.status_code == 200:
        return response.json()['resources']
    else:
        print(f'Failed to retrieve assets in site. Status code: {response.status_code}')
        return None

def find_site_id(site_name):
    url = f'{IVM_BASE_URL}/sites'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        sites = response.json()['resources']
        for site in sites:
            if site['name'] == site_name:
                return site['id']
    else:
        print(f'Failed to retrieve sites. Status code: {response.status_code}')

    return None

def get_included_asset_groups(site_id):
    url = f'{IVM_BASE_URL}/sites/{site_id}/included_asset_groups'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        asset_groups = response.json()['resources']
        for asset_group in asset_groups:
            print(f"Asset Group ID: {asset_group['id']}, Name: {asset_group['name']}")
        return asset_groups
    else:
        print(f'Failed to retrieve included asset groups. Status code: {response.status_code}')

#Assets Group

def list_asset_groups():
    url = f'{IVM_BASE_URL}/asset_groups'
    # Create a Basic Authentication header
    credentials = base64.b64encode(f'{IVM_USER}:{IVM_PASS}'.encode('utf-8')).decode('utf-8')
    headers = {
        'Authorization': f'Basic {credentials}'
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        return response.json()['resources']
    else:
        print(f'Failed to retrieve asset groups. Status code: {response.status_code}')
        return None
    
def get_assets_in_group(group_id):
    url = f'{IVM_BASE_URL}/asset_groups/{group_id}/assets'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    
    if response.status_code == 200:
        return response.json()['resources']
    else:
        print(f'Failed to retrieve assets in group. Status code: {response.status_code}')
        return None
    
#Assets

def get_asset_details(asset_id):
    url = f"{IVM_BASE_URL}/assets/{asset_id}"
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    
    if response.status_code == 200:
        asset_data = response.json()
        asset_info = {
            "id": asset_data.get("id"),
            "mac": asset_data.get("mac"),
            "address": asset_data.get("ip"),
            "name": asset_data.get("hostName"),
            "operating_system": asset_data.get("os"),
            "malware": asset_data["vulnerabilities"].get("malwareKits"),
            "exploits": asset_data["vulnerabilities"].get("exploits"),
            "vulnerabilities": asset_data["vulnerabilities"].get("total"),
            "risk_score": asset_data.get("riskScore"),
            "raw_risk_score": asset_data.get("rawRiskScore"),
            "database": [db["description"] for db in asset_data.get("databases", [])],
            # next scan, last scan in the future
        }
        return asset_info
    else:
        print(f"Failed to retrieve asset details. Status Code: {response.status_code}")
        return None

def get_vulnerabilities_for_asset(asset_id):
    url = f'{IVM_BASE_URL}/assets/{asset_id}/vulnerabilities'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        return response.json()['resources']
    else:
        print(f'Failed to retrieve vulnerabilities for asset. Status code: {response.status_code}')
        return []
    
def get_asset_id_by_ip(ip_address):
    url = f'{IVM_BASE_URL}/assets?ip={ip_address}'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        assets = response.json()['resources']
        if assets:
            return assets[0]['id']  # Assuming the IP address is unique
    return None

def get_vulnerabilities_by_ip(ip_address):
    asset_id = get_asset_id_by_ip(ip_address)
    if asset_id:
        return get_vulnerabilities_for_asset(asset_id)
    else:
        print(f'No asset found with IP address: {ip_address}')
        return None

def get_asset_tags(asset_id):
    url = f'{IVM_BASE_URL}/assets/{asset_id}/tags'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        tags = [tag['name'] for tag in response.json()['resources']]
        return tags
    else:
        print(f'Failed to retrieve tags. Status code: {response.status_code}')
        return None
    
def show_popup_info(asset_id): #Assets Popup (Modal)
    asset_details = get_asset_details(asset_id)
    if not asset_details:
        return None  # Handle error

    asset_tags = get_asset_tags(asset_id)
    
    info = {
        "IP-Address": asset_details['address'],
        "MAC-Address": asset_details['mac'],
        "OS": asset_details['operating_system'],
        "Raw Risk Score": asset_details['raw_risk_score'],
        "Context Driven Risk Score": asset_details['risk_score'],
        "Databases": asset_details['database'],
        "Tags": ', '.join(asset_tags)
    }
    return info

def process_asset_data(site_id):
    if site_id is not None:
        asset_groups = get_included_asset_groups(site_id)
        if asset_groups is not None:
            for group in asset_groups:
                asset_group_id = group['id']
                assets = get_assets_in_group(asset_group_id)
                asset_details_list_detail = []
                for asset_id in assets:
                    asset_details = get_asset_details(asset_id)
                    if asset_details is not None:
                        asset_data = {
                            "IP-Address": asset_details['address'],
                            "MAC-Address": asset_details['mac'],
                            "OS": asset_details['operating_system'],
                            "Raw Risk Score": asset_details['raw_risk_score'],
                            "Context Driven Risk Score": asset_details['risk_score'],
                            "Databases": asset_details['database'],
                            "Tags": ', '.join(get_asset_tags(asset_id)),
                            "Vulnerabilities": [get_vulnerability_details(vuln['id'])['title'] for vuln in get_vulnerabilities_for_asset(asset_id)]
                        }
                        asset_details_list_detail.append(asset_data)

                with open(f'apps/static/assets/data/asset_data_detail.json', 'w') as f:
                    json.dump(asset_details_list_detail, f, indent=4)

#Vulnerabilities

def get_exploits_for_vulnerability(vulnerability_id):
    url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}/exploits'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        return len(response.json()['resources'])
    else:
        print(f'Failed to retrieve exploits for vulnerability. Status code: {response.status_code}')
        return None

def get_affected_assets_for_vulnerability(vulnerability_id):
    url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}/assets'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        response_data = response.json()
        resources = response_data.get('resources', [])
        return [str(resource) for resource in resources]
    else:
        print(f'Failed to retrieve affected assets for vulnerability. Status code: {response.status_code}')
        return []
    
def get_vulnerability_details(vulnerability_id):
    url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        data = response.json()
        # Check if 'cves' is in data and it is not an empty list
        cves = data.get('cves', [])
        cves_value = ', '.join(cves) if cves else ""
        
        categories_str = data.get('categories', '')
        return {
            "title": data.get('title'),
            "Malware": data.get('malware'),
            "cvss_v2": data['cvss']['v2'].get('score') if 'v2' in data['cvss'] else None,
            "cvss_v3": data['cvss']['v3'].get('score') if 'v3' in data['cvss'] else None,
            "riskScore": data.get('riskScore'),
            "published": data.get('published'),
            "modified_on": data.get('modified'),
            "severity": data.get('severity'),
            "CVSSv2 Link": data['cvss'].get('v2', {}).get('vector', None),
            "CVSSv3 Link": data['cvss'].get('v3', {}).get('vector', None),
            "Published": data['published'],
            "Added": data['added'],
            "Categories": ', '.join(data['categories']) if categories_str else "",
            "CVES": cves_value,
        }
    else:
        print(f'Failed to retrieve vulnerability details. Status code: {response.status_code}')
        return None

def get_cves_data(vulnerability_id):
    url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        data = response.json()
        # Check if 'cves' is in data and it is not an empty list
        cves = data.get('cves', [])
        cves_value = ', '.join(cves) if cves else ""
        return cves_value
    else:
        print(f'Failed to retrieve cve. Status code: {response.status_code}')

def generate_vulnerability_table(siteid):
    unique_vulnerabilities = get_vulnerabilities_in_site(siteid)
    table_data = []
    vulnerabilities_count = 0
    for vulnerability_id in unique_vulnerabilities:
        vulnerability_details = get_vulnerability_details(vulnerability_id)
        exploits_count = get_exploits_for_vulnerability(vulnerability_id)
        affected_assets_count = get_affected_assets_for_vulnerability(vulnerability_id)
        if vulnerability_details is not None:
            row = {
                "Title": vulnerability_details.get("title"),
                "Malware": "Yes" if vulnerability_details.get("malware") else "No",
                "Exploits": exploits_count,
                "CVSS": vulnerability_details.get("cvss_v2"),
                "CVSSv3": vulnerability_details.get("cvss_v3"),
                "Risk": vulnerability_details.get("riskScore"),
                "Published On": vulnerability_details.get("published"),
                "Modified On": vulnerability_details.get("modified_on"),
                "Severity": vulnerability_details.get("severity"),
                "Instances": len(affected_assets_count),
            }
            table_data.append(row)
            vulnerabilities_count += 1

    # Save table data to a JSON file
    with open('apps/static/assets/data/site_8/vulnerability_table_data.json', 'w') as f:
        json.dump(table_data, f, indent=4)
    print(f"Total vulnerabilities processed: {vulnerabilities_count}")
                    
def get_vulnerability_references(vulnerability_id):
    url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}/references'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        #references = response.json()
        return
        #for resource in references['resources']:
            #print(f"Reference: {resource['reference']}, Source: {resource['source']}, Advisory Link: {resource['advisory']['href']}")
    else:
        print(f"Failed to retrieve references. Status code: {response.status_code}")
        
def get_vulnerabilities_details():
    url = f'{IVM_BASE_URL}/assets'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code != 200:
        print(f"Failed to retrieve assets. Status code: {response.status_code}")
        return

    assets = response.json()['resources']
    
    all_site_ids = [1, 2, 3, 4, 8, 9, 10, 11, 12, 13]  # Add all your site IDs here

    # Initialize API helper
    api = InsightVmApi(IVM_USER, IVM_PASS, False)
    search_filters = [
        {
            "field": "site-id",
            "operator": "in",
            "values": all_site_ids  # This now contains all your site IDs
        }
    ]
    assets = api.asset_search(search_filters, "all")
    vulnerabilities_details_list = []
    processed_vulnerabilities = set()
    for asset in assets:
        asset_id = asset['id']
        vulnerabilities = get_vulnerabilities_for_asset(asset_id)
        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability['id']
            # Check if we've already processed this vulnerability
            if vulnerability_id in processed_vulnerabilities:
                continue  # Skip this vulnerability

            processed_vulnerabilities.add(vulnerability_id)  # Mark this vulnerability as processed

            # Fetch details only once per vulnerability
            vulnerability_data = get_vulnerability_details(vulnerability_id)
            if not vulnerability_data:
                continue  # Skip if we couldn't fetch data for some reason

            affected_assets_details = get_affected_assets_for_vulnerability(vulnerability_id)

            # Use the fetched data directly, without repeated function calls
            vulnerability_details = {
                "Title": vulnerability_data.get('title'),
                "ID": vulnerability_id,  # This should be vulnerability_id, not vulnerability['id']
                "Severity": vulnerability_data.get('severity'),
                "Risk Score": vulnerability_data.get('riskScore'),
                "CVSSv2 Link": vulnerability_data.get('CVSSv2 Link'),
                "CVSSv2 Score": vulnerability_data.get('cvss_v2'),
                "CVSSv3 Link": vulnerability_data.get('CVSSv3 Link'),
                "CVSSv3 Score": vulnerability_data.get('cvss_v3'),
                "Published": vulnerability_data.get('Published'),
                "Added": vulnerability_data.get('Added'),
                "Modified": vulnerability_data.get('modified_on'),
                "Categories": ', '.join(vulnerability_data.get('Categories', '').split(', ')),
                "CVES": vulnerability_data.get('CVES', '').replace(',', ''),
                "Affected Assets": [int(asset) for asset in affected_assets_details],
            }

            vulnerabilities_details_list.append(vulnerability_details)    
        with open(f'apps/static/assets/data/vulnerabilities_details_data.json', 'w') as f:
            json.dump(vulnerabilities_details_list, f, separators=(',', ':'))
    
    return 

def get_cves_in_site(siteid):
    vulnerabilities = get_vulnerabilities_in_site(siteid)
    cves_set = set()
    for vulnerability in vulnerabilities:
        cves_data = get_cves_data(vulnerability)
        if cves_data:
            print(cves_data)
            cves_set.update(cves_data.split(', '))
    print(f'Number of CVEs retrieved: {len(cves_set)}')
    
    # Dumping data to a JSON file
    print(f'File name will be: apps/static/assets/data/site_8/all_cves_site_{siteid}.json')
    with open(f'apps/static/assets/data/site_8/all_cves_site_{siteid}.json', 'w') as f:
        json.dump(list(cves_set), f, indent=4)
    return

def get_solutions_in_site(siteid):
    vulnerabilities = get_vulnerabilities_in_site(siteid)
    solutions_dict = {}
    for vulnerability_id in vulnerabilities:
        url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}/solutions'
        response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
        if response.status_code == 200:
            solutions_ids = response.json()['resources']
            solutions_list = []  # Initialize an empty list for solutions
            for solution_id in solutions_ids:
                solution_data = get_solution_details(solution_id)
                if solution_data:
                    solutions_list.append({
                        "Solution ID": solution_id,
                        "Title": solution_data.get('summary', {}).get('html', ''),
                        "Steps": solution_data.get('steps', {}).get('html', '')
                    })
            solutions_dict[vulnerability_id] = solutions_list
        else:
            print(f'Failed to retrieve solutions for vulnerability {vulnerability_id}. Status code: {response.status_code}')
    
    print(f'File name will be: apps/static/assets/data/site_8/vulnerabilities_solutions_in_{siteid}.json')
    with open(f'apps/static/assets/data/site_8/vulnerabilities_solutions_in_{siteid}.json', 'w') as f:
        json.dump(solutions_dict, f, indent=4)

    return

def get_solution_details(solution_id):
    url = f'{IVM_BASE_URL}/solutions/{solution_id}'
    response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
    if response.status_code == 200:
        return(response.json())  # Print the response data
    else:
        print(f'Failed to retrieve solution details. Status code: {response.status_code}')
        return None

def get_references_in_site(siteid):
    vulnerabilities = get_vulnerabilities_in_site(siteid)
    references_dict = {}
    for vulnerability_id in vulnerabilities:
        url = f'{IVM_BASE_URL}/vulnerabilities/{vulnerability_id}/references'
        response = requests.get(url, auth=(IVM_USER, IVM_PASS), verify=False)
        if response.status_code == 200:
            references_data = response.json()['resources']
            references_list = []  # Initialize an empty list for references
            for reference in references_data:
                references_list.append({
                    "Source": reference.get('source'),
                    "Link": reference.get('advisory', {}).get('href', '')
                })
            references_dict[vulnerability_id] = references_list
        else:
            print(f'Failed to retrieve references for vulnerability {vulnerability_id}. Status code: {response.status_code}')
    
    # Saving to JSON
    print(f'File name will be: apps/static/assets/data/site_8/vulnerabilities_references_in_{siteid}.json')
    with open(f'apps/static/assets/data/site_8/vulnerabilities_references_in_{siteid}.json', 'w') as f:
        json.dump(references_dict, f, indent=4)

    return

        
def get_vulnerability_title(vulnerability_id):
    details = get_vulnerability_details(vulnerability_id)
    if details is not None:
        return details.get('title')
    return None

# Get all Data
def get_all_assets():
    all_site_ids = [1, 2, 3, 4, 8, 9, 10, 11, 12, 13]  # Add all your site IDs here

    # Initialize API helper
    api = InsightVmApi(IVM_USER, IVM_PASS, False)
    search_filters = [
        {
            "field": "site-id",
            "operator": "in",
            "values": all_site_ids  # This now contains all your site IDs
        }
    ]
    assets = api.asset_search(search_filters, "all")
    print(f"{len(assets)} assets matched filter {search_filters}")
    return assets

def get_assets_in_site(siteid):
    siteids = []
    siteids.append(siteid)
    # Initialize API helper
    api = InsightVmApi(IVM_USER, IVM_PASS, False)
    search_filters = [
        {
            "field": "site-id",
            "operator": "in",
            "values": siteids  # This now contains all your site IDs
        }
    ]
    assets = api.asset_search(search_filters, "all")
    print(f"{len(assets)} assets matched filter {search_filters}")
    return assets

def get_vulnerabilities_in_site(siteid):
    assets = get_assets_in_site(siteid)
    unique_vulnerabilities = set()
    for asset in assets:
        asset_id = asset['id']
        vulnerabilities = get_vulnerabilities_for_asset(asset_id)
        for vulnerability in vulnerabilities:
            unique_vulnerabilities.add(vulnerability['id'])
    print(f"Number of unique vulnerabilities found: {len(unique_vulnerabilities)}")
    return list(unique_vulnerabilities)

def get_all_vulnerabilities():
    assets = get_all_assets()
    unique_vulnerabilities = set()
    for asset in assets:
        asset_id = asset['id']
        vulnerabilities = get_vulnerabilities_for_asset(asset_id)
        for vulnerability in vulnerabilities:
            unique_vulnerabilities.add(vulnerability['id'])
    print(f"Number of unique vulnerabilities found: {len(unique_vulnerabilities)}")
    return list(unique_vulnerabilities)

def get_all_cves():
    vulnerabilities = get_all_vulnerabilities()
    cves_set = set()
    for vulnerability in vulnerabilities:
        cves_data = get_cves_data(vulnerability)
        if cves_data:
            print(cves_data)
            cves_set.update(cves_data.split(', '))
    print(f'Number of CVEs retrieved: {len(cves_set)}')
    
    # Dumping data to a JSON file
    with open('apps/static/assets/data/all_cves.json', 'w') as f:
        json.dump(list(cves_set), f, indent=4)
    return

#CVES 

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
    file_path = f"apps/static/assets/data/site_8/all_cves_site_{siteid}.json"
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data, file_path

def save_cve_details(cve_details, siteid):
    output_file_path = f"apps/static/assets/data/site_8/all_cves_details_site_{siteid}.json"
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

def matched():
    # Initialize API helper
    api = InsightVmApi(IVM_USER, IVM_PASS, False)
    # Search for all linux devices scanned in last 30 days
    search_filters = [
        {
            "field": "last-scan-date",
            "operator": "is-within-the-last",
            "value": 30
        },
        {
            "field": "operating-system",
            "operator": "contains",
            "value": "Linux"
        }
    ]
    #assets = api.asset_search(search_filters, "all")
    #print(f"{len(assets)} assets matched filter {search_filters}")

    all_site_ids = [1, 2, 3, 4, 8, 9, 10, 11, 12, 13]  # Add all your site IDs here

    search_filters = [
        {
            "field": "site-id",
            "operator": "in",
            "values": all_site_ids  # This now contains all your site IDs
        }
    ]
    #assets = api.asset_search(search_filters, "all")
    #print(f"{len(assets)} assets matched filter {search_filters}")

    # Search for all Linux or Mac devices
    search_filters = [
        {
            "field": "operating-system",
            "operator": "contains",
            "value": "Mac"
        },
        {
            "field": "operating-system",
            "operator": "contains",
            "value": "Linux"
        }
    ]
    assets = api.asset_search(search_filters, "any")
    print(f"{len(assets)} assets matched filter {search_filters}")
    return
    
if __name__ == "__main__":
    list_all_sites()
    site_name = 'KDO-TVM-Systeme'
    site_id = find_site_id(site_name)
    print(site_id)
    #get_solution_details("ssl-replace-self-signed-cert")
    #get_solution_details("7-zip-upgrade-23_00")
    #get_solutions_in_site(site_id)
    #get_references_in_site(site_id)
    #get_cve_details_for_site(site_id)
    #get_cves_in_site(site_id)
    #get_all_cves()
    #get_all_assets()
    #get_assets_in_site(site_id)
    #get_vulnerabilities_in_site(site_id)
    #number_of_assets = len(assets)
    #print(f"Number of assets in site '{site_name}': {number_of_assets}")
    #asset_ids, asset_count = get_all_assets()
    #matched()
    #if asset_ids is not None:
    #    print(asset_ids)
    #    print(asset_count)
    #print(get_vulnerability_details('apache-httpd-cve-2019-10092'))
    get_vulnerabilities_details()
    #if site_id is not None:
    
        #asset_groups = get_included_asset_groups(site_id)
        #process_asset_data(site_id)
        #if asset_groups is not None:
            #for group in asset_groups:
                #asset_group_id = group['id']
                #assets = get_assets_in_group(asset_group_id)
               # asset_details_list = []
                #for asset_id in assets:
                    #asset_details = get_asset_details(asset_id)
                    #if asset_details is not None:
                        #asset_details_list.append(asset_details)
                
                #with open(f'apps/static/assets/data/asset_data.json', 'w') as f:
                    #json.dump(asset_details_list, f, indent=4)
    #generate_vulnerability_table(site_id)
        #else:
          #  print(f'No asset groups found for site "{site_name}"')
    #else:
        #print(f'Site "{site_name}" not found')


