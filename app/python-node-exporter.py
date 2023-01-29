import requests
import http.server
import socketserver
import time
import os
import logging
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict
from tinydb import TinyDB, Query
from tinydbstorage.storage import MemoryStorage

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
verifySSL = os.getenv("VERIFY_SSL", 'False').lower() in ('true', '1', 't')
zvm_url = os.environ.get('ZVM_HOST', '192.168.50.60')
zvm_port = os.environ.get('ZVM_PORT', '443')
client_id = os.environ.get('CLIENT_ID', 'api-script')
client_secret = os.environ.get('CLIENT_SECRET', 'js51tDM8oappYUGRJBhF7bcsedNoHA5j')
LOGLEVEL = os.environ.get('LOGLEVEL', 'DEBUG').upper()

logging.basicConfig(filename='../logs/Log-Main.log', level=LOGLEVEL, format='%(relativeCreated)6d %(threadName)s %(message)s')
log = logging.getLogger("Node-Exporter")

log.debug("Running with Variables:\nVerify SSL: " + str(verifySSL) + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

# Global Variables
token = ""
lastStats = CaseInsensitiveDict()

def ZvmAuthHandler():
    log.debug("ZVMAuthHandler Thread Started")
    expiresIn = 0
    global token
    while True:
        if (expiresIn < 30):
            h = CaseInsensitiveDict()
            h["Content-Type"] = "application/x-www-form-urlencoded"

            d = CaseInsensitiveDict()
            d["client_id"] = client_id
            d["client_secret"] = client_secret
            d["grant_type"] = "client_credentials"

            uri = "https://" + zvm_url + ":" + zvm_port + "/auth/realms/zerto/protocol/openid-connect/token"
            response = requests.post(url=uri, data=d, headers=h, verify=verifySSL)

            responseJSON = response.json()
            log.debug(responseJSON)
            token = str(responseJSON['access_token'])
            expiresIn = int(responseJSON['expires_in'])
        expiresIn = expiresIn - 10
        log.debug("Token Expires in " + str(expiresIn) + " seconds")
        time.sleep(10)


def GetDataFunc():
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    while (True) :
        global token

        if (token != ""):
            log.info("Got Auth Token!")
            log.debug("token: " + str(token))
            log.debug("Data Collector Loop Running")
            
            metricsDictionary = {}

            h2 = CaseInsensitiveDict()
            h2["Accept"] = "application/json"
            h2["Authorization"] = "Bearer " + token
            

            ### VPGs API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vpgs/"
            service = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
            vpg_json  = service.json()
            log.debug(vpg_json)
            for vpg in vpg_json :
                metricsDictionary["vpg_storage_used_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["UsedStorageInMB"]
                metricsDictionary["vpg_actual_rpo{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ActualRPO"]
                metricsDictionary["vpg_throughput_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ThroughputInMB"]
                metricsDictionary["vpg_iops{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["IOPs"]
                metricsDictionary["vpg_provisioned_storage_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ProvisionedStorageInMB"]
                metricsDictionary["vpg_vms_count{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["VmsCount"]
                metricsDictionary["vpg_configured_rpo_seconds{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["ConfiguredRpoSeconds"]
                metricsDictionary["vpg_actual_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
                metricsDictionary["vpg_configured_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\"}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]

            ### Datastores APIs
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/datastores/"
            service = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
            ds_json  = service.json()
            log.debug(ds_json)
            for ds in ds_json :
                metricsDictionary["datastore_health_status{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Health"]["Status"]
                metricsDictionary["datastore_vras{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["NumVRAs"]
                metricsDictionary["datastore_incoming_vms{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["NumIncomingVMs"]
                metricsDictionary["datastore_outgoing_vms{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["NumOutgoingVMs"]
                metricsDictionary["datastore_usage_capacityinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["CapacityInBytes"]
                metricsDictionary["datastore_usage_freeinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["FreeInBytes"]
                metricsDictionary["datastore_usage_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["UsedInBytes"]
                metricsDictionary["datastore_usage_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_protected_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Protected"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_protected_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Protected"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_recovery_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Recovery"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_recovery_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Recovery"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_journal_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Journal"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_journal_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Journal"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_scratch_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Scratch"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_scratch_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Scratch"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_appliances_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Appliances"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_appliances_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Appliances"]["ProvisionedInBytes"]

            ## VMs API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/"
            vmapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
            vmapi_json  = vmapi.json()
            log.debug(vmapi_json)
            for vm in vmapi_json :
                metricsDictionary["vm_actualrpo{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["ActualRPO"]
                metricsDictionary["vm_throughput_in_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["ThroughputInMB"]
                metricsDictionary["vm_iops{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["IOPs"]
                metricsDictionary["vm_journal_hard_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalHardLimit"]["LimitValue"]
                metricsDictionary["vm_journal_used_storage_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["JournalUsedStorageMb"]
                metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\"}"] = vm["OutgoingBandWidthInMbps"]
                #metricsDictionary["vm_actual_rpo{VmName=\"" + vpg['VmName'] + "\"}"] = vm["actualRPO"]

            ## Volumes API
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
            
            ## Statistics API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/statistics/vms/"
            statsapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
            statsapi_json  = statsapi.json()
            log.debug(statsapi_json)
            for vm in statsapi_json:
                log.debug(vm)
                oldvmdata = dict()

                CurrentIops                       = 0
                CurrentWriteCounterInMBs          = 0
                CurrentSyncCounterInMBs           = 0
                CurrentNetworkTrafficCounterInMBs = 0
                CurrentEncryptedLBs               = 0
                CurrentUnencryptedLBs             = 0
                CurrentTotalLBs                   = 0
                CurrentPercentEncrypted           = 0
                VMName                            = "NA"

                oldvmdata = tempdb.search(dbvm.VmIdentifier == vm['VmIdentifier'])
                log.debug("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                log.debug("All Database")
                log.debug(tempdb.all())
                log.debug("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                log.debug("Checking TempDB for VM " + vm['VmIdentifier'])
                if (oldvmdata):
                    log.debug("Record Found")
                    log.debug("_*_*_*_*_*_*_*_*")
                    log.debug(oldvmdata[0])
                    log.debug("_*_*_*_*_*_*_*_*")
                    log.debug(tempdb.update(vm, dbvm.VmIdentifier == vm['VmIdentifier']))

                    log.debug("!@!@!@!@!@  Stats  !@!@!@!@!@")
                    VMName                            = oldvmdata[0]['VmName']
                    log.debug("Current VM " + str(VMName))
                    CurrentIops                       = vm['IoOperationsCounter'] - oldvmdata[0]['IoOperationsCounter']
                    log.debug("CurrentIops " + str(CurrentIops))
                    CurrentSyncCounterInMBs           = vm['SyncCounterInMBs'] - oldvmdata[0]['SyncCounterInMBs']
                    log.debug("CurrentSyncCounterInMBs " + str(CurrentSyncCounterInMBs))
                    CurrentNetworkTrafficCounterInMBs = vm['NetworkTrafficCounterInMBs'] - oldvmdata[0]['NetworkTrafficCounterInMBs']
                    log.debug("CurrentNetworkTrafficCounterInMBs " + str(CurrentNetworkTrafficCounterInMBs))
                    CurrentEncryptedLBs               = vm['EncryptionStatistics']['EncryptedDataInLBs'] - oldvmdata[0]['EncryptionStatistics']['EncryptedDataInLBs']
                    log.debug("CurrentEncryptedLBs " + str(CurrentEncryptedLBs))
                    CurrentUnencryptedLBs             = vm['EncryptionStatistics']['UnencryptedDataInLBs'] - oldvmdata[0]['EncryptionStatistics']['UnencryptedDataInLBs']
                    log.debug("CurrentUnencryptedLBs " + str(CurrentUnencryptedLBs))
                    CurrentTotalLBs                   = CurrentEncryptedLBs + CurrentUnencryptedLBs
                    log.debug("CurrentTotalLBs " + str(CurrentTotalLBs))
                    if CurrentTotalLBs != 0:
                        CurrentPercentEncrypted       = ((CurrentEncryptedLBs / CurrentTotalLBs) * 100)
                    else:
                        CurrentPercentEncrypted       = 0
                    log.debug("CurrentPercentEncrypted " + str(CurrentPercentEncrypted))

                else:
                    log.debug("No Record")
                    #insert original VM record to tempdb
                    log.debug(tempdb.insert(vm))

                    # update database with VM name, for easier display in Grafana Legends
                    uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/" + vm['VmIdentifier']
                    vapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                    vapi_json  = vapi.json()
                    log.debug("!@!@!@!@!@!@!@!@!@!@!@")
                    log.debug(vapi_json)
                    log.debug("!@!@!@!@!@!@!@!@!@!@!@")
                    tempdb.update({'VmName': vapi_json['VmName']}, dbvm.VmIdentifier == vm['VmIdentifier'])
                    VMName = vapi_json['VmName']

                # Store Calculated Metrics
                metricsDictionary["vm_IoOperationsCounter{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentIops
                metricsDictionary["vm_WriteCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentWriteCounterInMBs
                metricsDictionary["vm_SyncCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentSyncCounterInMBs
                metricsDictionary["vm_NetworkTrafficCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentNetworkTrafficCounterInMBs
                metricsDictionary["vm_EncryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentEncryptedLBs
                metricsDictionary["vm_UnencryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentUnencryptedLBs
                metricsDictionary["vm_TotalDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentTotalLBs
                metricsDictionary["vm_PercentEncrypted{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName + "\"}"] = CurrentPercentEncrypted

            # open file to write new data
            #file_object = open('metrics.txt', 'w')
            #for item in metricsDictionary :
            #    file_object.write(item)
            #    file_object.write(" ")
            #    file_object.write(str(metricsDictionary[item]))
            #    file_object.write("\n")
            
            file_object = open('metrics', 'w')
            for item in metricsDictionary :
                file_object.write(item)
                file_object.write(" ")
                file_object.write(str(metricsDictionary[item]))
                file_object.write("\n")

            # This function will get data every 10 seconds
            log.debug("Starting Sleep")
            time.sleep(10)
        else:
            log.debug("Waiting 1 second for Auth Token")
            time.sleep(1)

#-------Start function to maintain ZVM Authentication---------
# run ZvmAuthHandler func in the background
background_thread = Thread(target = ZvmAuthHandler)
background_thread.start()

#-----------------Start Data collector Thread-----------------
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
