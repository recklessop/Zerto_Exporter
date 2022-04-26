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
            metricsDictionary["vpg-storage-used-in-mb{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["UsedStorageInMB"]
            metricsDictionary["vpg-actual-rpo{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["ActualRPO"]
            metricsDictionary["vpg-throughput-in-mb{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["ThroughputInMB"]
            metricsDictionary["vpg-iops{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["IOPs"]
            metricsDictionary["vpg-provisioned-storage-in-mb{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["ProvisionedStorageInMB"]
            metricsDictionary["vpg-vms-count{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["VmsCount"]
            metricsDictionary["vpg-configured-rpo-seconds{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["ConfiguredRpoSeconds"]
            metricsDictionary["vpg-actual-history-in-minutes{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
            metricsDictionary["vpg-configured-history-in-minutes{VpgIdentifier=" + vpg['VpgIdentifier'] + ",VpgName=" + vpg['VpgName'] + "}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]

        vmapi = requests.get("https://192.168.52.30/v1/vms/",timeout=3, headers=h2, verify=verifySSL)
        vmapi_json  = vmapi.json()

        for vm in vmapi_json :
            metricsDictionary["vm-actual-rpo{VmName=" + vm['VmName'] + "}"] = vm["ActualRPO"]
            metricsDictionary["vm-throughput-in-mb{VmName=" + vm['VmName'] + "}"] = vm["ThroughputInMB"]
            metricsDictionary["vm-iops{VmName=" + vm['VmName'] + "}"] = vm["IOPs"]
            metricsDictionary["vm-journal-used-storage-MB{VmName=" + vm['VmName'] + "}"] = vm["JournalUsedStorageMb"]
            metricsDictionary["vm-outgoing-bandwidth-in-mbps{VmName=" + vm['VmName'] + "}"] = vm["OutgoingBandWidthInMbps"]
            #metricsDictionary["vm-actual-rpo{VmName=" + vpg['VmName'] + "}"] = vm["actualRPO"]


        # This function will get data every 5 seconds
        time.sleep(5)

        # open file to write new data
        file_object = open('metrics.txt', 'w')
        for item in metricsDictionary :
            file_object.write("\n")
            file_object.write(item)
            file_object.write(" ")
            file_object.write(str(metricsDictionary[item]))


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