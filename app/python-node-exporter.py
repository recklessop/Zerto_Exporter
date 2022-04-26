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
            metricsDictionary["vpgstorageusedinmb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["UsedStorageInMB"]
            metricsDictionary["vpgactualrpo{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ActualRPO"]
            metricsDictionary["vpgthroughputinmb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ThroughputInMB"]
            metricsDictionary["vpgiops{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["IOPs"]
            metricsDictionary["vpgprovisionedstorageinmb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ProvisionedStorageInMB"]
            metricsDictionary["vpgvmscount{VpgIdentifier=\"" + vpg['VpgIdentifier'] + ",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["VmsCount"]
            metricsDictionary["vpgconfiguredrposeconds{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ConfiguredRpoSeconds"]
            metricsDictionary["vpgactualhistoryinminutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
            metricsDictionary["vpgconfiguredhistoryinminutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]

        vmapi = requests.get("https://192.168.52.30/v1/vms/",timeout=3, headers=h2, verify=verifySSL)
        vmapi_json  = vmapi.json()

        for vm in vmapi_json :
            metricsDictionary["vmactualrpo{VmName=\"" + vm['VmName'] + "\"}"] = vm["ActualRPO"]
            metricsDictionary["vmthroughputinmb{VmName=" + vm['VmName'] + "\"}"] = vm["ThroughputInMB"]
            metricsDictionary["vmiops{VmName=\"" + vm['VmName'] + "\"}"] = vm["IOPs"]
            metricsDictionary["vmjournalusedstoragemb{VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalUsedStorageMb"]
            metricsDictionary["vmoutgoingbandwidthinmbps{VmName=\"" + vm['VmName'] + "\"}"] = vm["OutgoingBandWidthInMbps"]
            #metricsDictionary["vmactualrpo{VmName=\"" + vpg['VmName'] + "\"}"] = vm["actualRPO"]


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