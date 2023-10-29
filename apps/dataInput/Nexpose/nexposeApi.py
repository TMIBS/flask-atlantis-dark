from urllib import response
import requests
import json
import getpass
import os


# Konfiguration für die API
IVM_BASE_URL = 'https://nexpose.kdo.de:3780/api/3'
IVM_USER = input('Benutzername:')
IVM_PASS = input('Passwort:')

# API Aufruf
resp = requests.put(url=IVM_BASE_URL, auth=(IVM_USER, IVM_PASS), verify=False)

if resp.status_code != 200:
    print('ERROR')
    print(response.text)
    vars(resp)

# setzt das Tag für ein einzelnes Asset -> wird in assign_tag() benutzt
# assetId = interne ID des jeweiligen Assets aus Nexpose
# tagName = Teamname aus IPAM zur Zuordnung des Tags
def set_tag(assetId, tagName):
    teamsdict = {}
    teamslist = open('temp/listAllTags.json')
    teams = json.load(teamslist)
    for resource in teams['resources']:
        teamsdict[resource['name']] = resource['id']
    if 'WEB'.upper() in tagName.upper():
        tagName = 'WEB'
    elif 'APR'.upper() in tagName.upper():
        tagName = 'TVM'
    elif 'TVM'.upper() in tagName.upper():
        tagName = 'TVM'
    elif 'WAN'.upper() in tagName.upper():
        tagName = 'WAN'
    elif 'EuF'.upper() in tagName.upper():
        tagName = 'TVM'
    elif 'SAP'.upper() in tagName.upper():
        tagName = 'TSA'
    elif 'LIN'.upper() in tagName.upper():
        tagName = 'LIN'
    elif 'TSA'.upper() in tagName.upper():
        tagName = 'TSA'
    elif 'VM'.upper() in tagName.upper():
        tagName = 'VM'
    elif 'TiD'.upper() in tagName.upper():
        tagName = 'TID'   
    print(assetId)
    tagId = teamsdict[tagName]
    url = IVM_BASE_URL+'/assets/{}/tags/{}'.format(assetId, tagId)
    
    # API Aufruf
    resp = requests.put(url=url, auth=(IVM_USER, IVM_PASS), verify=False)

    if resp.status_code != 200:
        print('ERROR')
        vars(resp)

# löscht das einzelne Tag von einem Asset
# assetId = interne ID des jeweiligen Assets aus Nexpose
# tagName = Name des bisherigen Tags in Nexpose
def delete_tag(assetId, tagName):
    teamsdict = {}
    teamslist = open('temp/listAllTags.json')
    teams = json.load(teamslist)
    for resource in teams['resources']:
        teamsdict[resource['name']] = resource['id']
    tagId = teamsdict[tagName]

    url = IVM_BASE_URL+'/assets/{}/tags/{}'.format(assetId, tagId)

    # API Aufruf
    resp = requests.delete(url=url, auth=(IVM_USER, IVM_PASS), verify=False)

    if resp.status_code != 200:
        print('ERROR')
        vars(resp)


# ruft alle Tags aus Nexpose ab und erstellt eine Liste
def get_tags():
    url = IVM_BASE_URL+'/tags?size=500'
    # GET /api/3/tags
    resp = requests.get(url=url, auth=(IVM_USER, IVM_PASS),verify=False)
    output = resp.json()
    with open('temp/listAllTags.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=4)

    if resp.status_code != 200:
        print('ERROR')
        vars(resp)

def get_reportID(name):
    url = IVM_BASE_URL+'/reports'
    response = requests.get(url=url, auth=(IVM_USER, IVM_PASS), verify=False)
    

    if response.status_code == 200:
        scan_data = response.json()["resources"]
        currentpage = 1
        totalsites = response.json()['page']['totalPages']

        while not (currentpage > totalsites):
            if len(scan_data) > 0:
                for item in scan_data:
                    if name == item['name'] :
                        #print("Report gefunden:" + item['name'])
                        return item['id']
            currentpage += 1
            url = IVM_BASE_URL+'/reports?page='+str(currentpage-1)
            response = requests.get(url=url, auth=(IVM_USER, IVM_PASS), verify=False)
            scan_data = response.json()["resources"]
            

        print("Keine Scan Daten gefunden.")
    else:
        print(f"Abrufen der scan_id fehlgeschlagen. Status Code: {response.status_code}")

def get_report(report_name):
    report_id = get_reportID(report_name)
    url = IVM_BASE_URL+'/reports/{}/history/latest/output'.format(report_id)
    response = requests.get(url=url, auth=(IVM_USER, IVM_PASS),verify=False)

    if response.status_code == 200:
        path = os.getcwd()      
        file_path = path+'/Nexpose_Reports/'+report_name
        with open(file_path, "wb") as f:
            f.write(response.content)

            print("Report erfolgreich heruntergeladen")
        return file_path
    else:
        print("Fehler beim Herunterladen des Reports")

def get_inActiveAssets(scansite_id):
    url = IVM_BASE_URL+'/sites/'+str(scansite_id)+'/assets?inactive=true'
    response = requests.get(url=url, auth=(IVM_USER, IVM_PASS),verify=False)
    # Überprüfen der Antwort auf Erfolg oder Fehler
    if response.status_code == 200:
        # Die Liste der inaktiven Assets abrufen
        inactive_assets = response.json()

        # Inaktive Assets anzeigen
        for asset in inactive_assets:
            asset_name = asset['hostName']
            print(f"Inactive Asset: {asset_name}")

    else:
        print('Failed to retrieve inactive assets:', response.text)
        
if __name__ == "__main__":
    get_tags()