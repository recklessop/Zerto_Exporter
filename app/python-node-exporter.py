import requests
import http.server
import socketserver
import time
import os
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
verifySSL = os.getenv("VERIFY_SSL", 'False').lower() in ('true', '1', 't')
zvm_url = os.environ['ZVM_HOST']
zvm_port = os.environ['ZVM_PORT']
client_id = os.environ['CLIENT_ID']
client_secret = os.environ['CLIENT_SECRET']

print("Running with Variables:\nVerify SSL: " + os.environ['VERIFY_SSL'] + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

def GetDataFunc():
    while True :
        h = CaseInsensitiveDict()
        h["Content-Type"] = "application/x-www-form-urlencoded"

        d = CaseInsensitiveDict()
        d["client_id"] = client_id
        d["client_secret"] = client_secret
        d["grant_type"] = "client_credentials"

        uri = "https://" + zvm_url + ":" + zvm_port + "/auth/realms/zerto/protocol/openid-connect/token"
        response = requests.post(url=uri, data=d, headers=h, verify=verifySSL)

        token = response.json()

        h2 = CaseInsensitiveDict()
        h2["Accept"] = "application/json"
        h2["Authorization"] = "Bearer " + token['access_token']

        uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vpgs/"
        service = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
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

        uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/"
        vmapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
        vmapi_json  = vmapi.json()

        for vm in vmapi_json :
            metricsDictionary["vm_actualrpo{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["ActualRPO"]
            metricsDictionary["vm_throughput_in_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["ThroughputInMB"]
            metricsDictionary["vm_iops{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["IOPs"]
            metricsDictionary["vm_journal_hard_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalHardLimit"]["LimitValue"]
            metricsDictionary["vm_journal_used_storage_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalUsedStorageMb"]
            metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["OutgoingBandWidthInMbps"]
            #metricsDictionary["vm_actual_rpo{VmName=\"" + vpg['VmName'] + "\"}"] = vm["actualRPO"]

        uri = "https://" + zvm_url + ":" + zvm_port + "/v1/statistics/vms/"
        statsapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
        statsapi_json  = statsapi.json()

        for vm in statsapi_json :
            metricsDictionary["vm_IoOperationsCounter{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["IoOperationsCounter"]
            metricsDictionary["vm_WriteCounterInMBs{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["WriteCounterInMBs"]
            metricsDictionary["vm_SyncCounterInMBs{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["SyncCounterInMBs"]
            metricsDictionary["vm_NetworkTrafficCounterInMBs{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["NetworkTrafficCounterInMBs"]
            #metricsDictionary["vm_SampleTime{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["SampleTime"]
            metricsDictionary["vm_EncryptedDataInLBs{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["EncryptionStatistics"]["EncryptedDataInLBs"]
            metricsDictionary["vm_UnencryptedDataInLBs{VmIdentifier=\"" + vm['VmIdentifier'] + "\"}"] = vm["EncryptionStatistics"]["UnencryptedDataInLBs"]

        uri = "https://" + zvm_url + ":" + zvm_port + "/v1/volumes?volumeType=scratch"
        volapi = requests.get(url=uri, timeout=5, headers=h2, verify=verifySSL)
        volapi_json  = volapi.json()

        if(bool(volapi_json)):
            for volume in volapi_json :
                #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                metrickey = "scratch_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"
                if (metrickey in metricsDictionary):
                    metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                else:
                    metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]
                percentage_used = (volume["Size"]["UsedInBytes"] / volume["Size"]["ProvisionedInBytes"] * 100)
                percentage_used = round(percentage_used, 1)
                #metricsDictionary["scratch_volume_percentage_used{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = percentage_used

        # This function will get data every 5 seconds
        time.sleep(5)

        # open file to write new data
        file_object = open('metrics', 'w')
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
