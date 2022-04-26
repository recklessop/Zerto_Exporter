import requests
import http.server
import socketserver
import time
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
verifySSL = False
zvm_url = "192.168.52.30"
zvm_port = "443"

def GetDataFunc():
    while True :
        h = CaseInsensitiveDict()
        h["Content-Type"] = "application/x-www-form-urlencoded"

        d = CaseInsensitiveDict()
        d["client_id"] = "my-script-client"
        d["client_secret"] = "c2c117be-504d-41f7-b29f-29fcaee6682a"
        d["grant_type"] = "client_credentials"

        response = requests.post('https://192.168.52.30/auth/realms/zerto/protocol/openid-connect/token', data=d, headers=h, verify=verifySSL)

        token = response.json()

        h2 = CaseInsensitiveDict()
        h2["Accept"] = "application/json"
        h2["Authorization"] = "Bearer " + token['access_token']

        service = requests.get("https://192.168.52.30/v1/vpgs/",timeout=3, headers=h2, verify=verifySSL)
        service_json  = service.json()

        metricsDictionary = {}
        for vpg in service_json :
            metricsDictionary["vpg_storage_used_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["UsedStorageInMB"]
            metricsDictionary["vpg_actual_rpo{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ActualRPO"]
            metricsDictionary["vpg_throughput_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ThroughputInMB"]
            metricsDictionary["vpg_iops{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["IOPs"]
            metricsDictionary["vpg_provisioned_storage_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ProvisionedStorageInMB"]
            metricsDictionary["vpg_vms_count{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["VmsCount"]
            metricsDictionary["vpg_configured_rpo_seconds{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ConfiguredRpoSeconds"]
            metricsDictionary["vpg_actual_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
            metricsDictionary["vpg_configured_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]

        vmapi = requests.get("https://192.168.52.30/v1/vms/",timeout=3, headers=h2, verify=verifySSL)
        vmapi_json  = vmapi.json()

        for vm in vmapi_json :
            metricsDictionary["vm_actualrpo{VmName=\"" + vm['VmName'] + "\"}"] = vm["ActualRPO"]
            metricsDictionary["vm_throughput_in_mb{VmName=" + vm['VmName'] + "\"}"] = vm["ThroughputInMB"]
            metricsDictionary["vm_iops{VmName=\"" + vm['VmName'] + "\"}"] = vm["IOPs"]
            metricsDictionary["vm_journal_used_storage_mb{VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalUsedStorageMb"]
            metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmName=\"" + vm['VmName'] + "\"}"] = vm["OutgoingBandWidthInMbps"]
            #metricsDictionary["vm_actual_rpo{VmName=\"" + vpg['VmName'] + "\"}"] = vm["actualRPO"]


        # This function will get data every 5 seconds
        time.sleep(5)

        # open file to write new data
        file_object = open('metrics.txt', 'w')
        for item in metricsDictionary :
            file_object.write(item)
            file_object.write(" ")
            file_object.write(str(metricsDictionary[item]))
            file_object.write("\n")


# run GetDataFunc func in the background
background_thread = Thread(target = GetDataFunc)
background_thread.start()


#----------------run http server on port 9999-----------------

def WebServer():
    PORT = 9999

    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()


# run WebServer func in the background
background_thread = Thread(target = WebServer)
background_thread.start()