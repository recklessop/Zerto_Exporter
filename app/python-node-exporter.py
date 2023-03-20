import requests
import http.server
import socketserver
import time
import os
import logging
import threading
from logging.handlers import RotatingFileHandler
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
scrape_speed = int(os.environ.get('SCRAPE_SPEED', 30))
api_timeout = int(os.environ.get('API_TIMEOUT', 5))
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()

#log_formatter = logging.Formatter('%(relativeCreated)6d %(threadName)s %(message)s')
log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")

log_handler = RotatingFileHandler(filename='../logs/Log-Main.log', maxBytes=1024*1024*100, backupCount=5)
log_handler.setFormatter(log_formatter)

log = logging.getLogger("Node-Exporter")
log.setLevel(LOGLEVEL)
log.addHandler(log_handler)

log.debug("Running with Variables:\nVerify SSL: " + str(verifySSL) + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

# Global Variables
token = ""
lastStats = CaseInsensitiveDict()

def ZvmAuthHandler():
    log.debug("ZVMAuthHandler Thread Started")
    expiresIn = 0
    global token
    retries = 0
    while True:
        if expiresIn < 30:
            h = CaseInsensitiveDict()
            h["Content-Type"] = "application/x-www-form-urlencoded"

            d = CaseInsensitiveDict()
            d["client_id"] = client_id
            d["client_secret"] = client_secret
            d["grant_type"] = "client_credentials"

            uri = "https://" + zvm_url + ":" + zvm_port + "/auth/realms/zerto/protocol/openid-connect/token"
            delay = 0

            try:
                response = requests.post(url=uri, data=d, headers=h, verify=verifySSL)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                retries += 1
                delay = 2 ** retries
                log.error("Error while sending authentication request: " + str(e) + ". Retrying in " + str(delay) + " seconds")
                time.sleep(delay)
                continue
            else:
                retries = 0
            
            responseJSON = response.json()
            if 'access_token' not in responseJSON or 'expires_in' not in responseJSON:
                log.error("Authentication response does not contain expected keys")
                delay = 2 ** retries
                time.sleep(delay)
                retries += 1
                continue
            
            token = str(responseJSON.get('access_token'))
            expiresIn = int(responseJSON.get('expires_in'))
            
            if response.status_code != 200:
                log.error("Authentication request failed with status code " + str(response.status_code))
                delay = 2 ** retries
                time.sleep(delay)
                retries += 1
                continue
                
        expiresIn -= 10 + delay
        log.debug("Token Expires in " + str(expiresIn) + " seconds")
        time.sleep(10)


def GetStatsFunc():
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
            
            ## Statistics API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/statistics/vms/"
            statsapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
            statsapi_json  = statsapi.json()
            #log.debug(statsapi_json)
            for vm in statsapi_json:
                #log.debug(vm)
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
                #log.debug("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                #log.debug("All Database")
                #log.debug(tempdb.all())
                #log.debug("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                log.info("Checking TempDB for VM " + vm['VmIdentifier'])
                if (oldvmdata):
                    log.info(vm['VmIdentifier'] + " Record Found")
                    log.debug("_*_*_*_*_*_*_*_*")
                    log.debug(oldvmdata[0])
                    log.debug("_*_*_*_*_*_*_*_*")
                    log.debug(tempdb.update(vm, dbvm.VmIdentifier == vm['VmIdentifier']))

                    log.debug("!@!@!@!@!@  Stats  !@!@!@!@!@")
                    VMName                            = oldvmdata[0]['VmName']
                    log.debug("Current VM " + str(VMName))
                    CurrentIops                       = abs(vm['IoOperationsCounter'] - oldvmdata[0]['IoOperationsCounter'])
                    log.debug("CurrentIops " + str(CurrentIops))
                    CurrentSyncCounterInMBs           = abs(vm['SyncCounterInMBs'] - oldvmdata[0]['SyncCounterInMBs'])
                    log.debug("CurrentSyncCounterInMBs " + str(CurrentSyncCounterInMBs))
                    CurrentNetworkTrafficCounterInMBs = abs(vm['NetworkTrafficCounterInMBs'] - oldvmdata[0]['NetworkTrafficCounterInMBs'])
                    log.debug("CurrentNetworkTrafficCounterInMBs " + str(CurrentNetworkTrafficCounterInMBs))
                    CurrentEncryptedLBs               = abs(vm['EncryptionStatistics']['EncryptedDataInLBs'] - oldvmdata[0]['EncryptionStatistics']['EncryptedDataInLBs'])
                    log.debug("CurrentEncryptedLBs " + str(CurrentEncryptedLBs))
                    CurrentUnencryptedLBs             = abs(vm['EncryptionStatistics']['UnencryptedDataInLBs'] - oldvmdata[0]['EncryptionStatistics']['UnencryptedDataInLBs'])
                    log.debug("CurrentUnencryptedLBs " + str(CurrentUnencryptedLBs))
                    CurrentTotalLBs                   = abs(CurrentEncryptedLBs + CurrentUnencryptedLBs)
                    log.debug("CurrentTotalLBs " + str(CurrentTotalLBs))
                    if CurrentTotalLBs != 0:
                        CurrentPercentEncrypted       = ((CurrentEncryptedLBs / CurrentTotalLBs) * 100)
                    else:
                        CurrentPercentEncrypted       = 0
                    log.debug("CurrentPercentEncrypted " + str(CurrentPercentEncrypted))

                else:
                    log.info(vm['VmIdentifier'] + " No Record Found")
                    #insert original VM record to tempdb
                    log.debug(tempdb.insert(vm))

                    # update database with VM name, for easier display in Grafana Legends
                    uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/" + vm['VmIdentifier']
                    vapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                    vapi_json  = vapi.json()
                    #log.debug("!@!@!@!@!@!@!@!@!@!@!@")
                    #log.debug(vapi_json)
                    #log.debug("!@!@!@!@!@!@!@!@!@!@!@")
                    tempdb.update({'VmName': vapi_json['VmName']}, dbvm.VmIdentifier == vm['VmIdentifier'])
                    log.info(vm['VmIdentifier'] + " Added to temp vm db")
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

            ## Write metrics to a human readable metrics.txt file as well as a metrics file that is easy to get in prometheus
            file_object = open('statsmetrics', 'w')
            txt_object = open('statsmetrics.txt', 'w')
            for item in metricsDictionary :
                file_object.write(item)
                file_object.write(" ")
                file_object.write(str(metricsDictionary[item]))
                file_object.write("\n")
                txt_object.write(item)
                txt_object.write(" ")
                txt_object.write(str(metricsDictionary[item]))
                txt_object.write("\n")
            file_object.close()
            txt_object.close()

            log.debug("Starting Sleep for " + str(scrape_speed) + " seconds")
            time.sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            time.sleep(1)


def GetDataFunc():
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    while (True) :
        global token

        if (token != ""):
            log.debug("Got Auth Token!")
            log.debug("token: " + str(token))
            log.info("Data Collector Loop Running")
            
            metricsDictionary = {}

            h2 = CaseInsensitiveDict()
            h2["Accept"] = "application/json"
            h2["Authorization"] = "Bearer " + token
            

            ### VPGs API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vpgs/"
            service = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            vpg_json  = service.json()
            #log.debug(vpg_json)
            for vpg in vpg_json :
                metricsDictionary["vpg_storage_used_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["UsedStorageInMB"]
                metricsDictionary["vpg_actual_rpo{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["ActualRPO"]
                metricsDictionary["vpg_throughput_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["ThroughputInMB"]
                metricsDictionary["vpg_iops{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["IOPs"]
                metricsDictionary["vpg_provisioned_storage_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["ProvisionedStorageInMB"]
                metricsDictionary["vpg_vms_count{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["VmsCount"]
                metricsDictionary["vpg_configured_rpo_seconds{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["ConfiguredRpoSeconds"]
                metricsDictionary["vpg_actual_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
                metricsDictionary["vpg_configured_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]
                metricsDictionary["vpg_failsafe_history_in_minutes_actual{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["FailSafeHistory"]["ActualFailSafeHistory"]
                metricsDictionary["vpg_failsafe_history_in_minutes_configured{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["FailSafeHistory"]["ConfiguredFailSafeHistory"]
                metricsDictionary["vpg_status{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["Status"]
                metricsDictionary["vpg_substatus{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["SubStatus"]
                metricsDictionary["vpg_alert_status{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority']) + "\"}"] = vpg["AlertStatus"]

            ### Datastores APIs
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/datastores/"
            service = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            ds_json  = service.json()
            #log.debug(ds_json)
            for ds in ds_json :
                log.debug("!!!!!!!!!!!!!!!! Datastore Info!!!!!!!!!!!!!!!!!")
                log.debug(ds['DatastoreName'])
                #log.debug(ds["Health"]["Status"])
                log.debug(ds["Stats"]["NumVRAs"])
                log.debug(ds["Stats"]["NumIncomingVMs"])
                log.debug(ds["Stats"]["NumOutgoingVMs"])
                log.debug(ds["Stats"]["Usage"]["Datastore"]["CapacityInBytes"])
                log.debug(ds["Stats"]["Usage"]["Datastore"]["FreeInBytes"])
                log.debug(ds["Stats"]["Usage"]["Datastore"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Datastore"]["ProvisionedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Protected"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Protected"]["ProvisionedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Recovery"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Recovery"]["ProvisionedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Journal"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Journal"]["ProvisionedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Scratch"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Scratch"]["ProvisionedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Appliances"]["UsedInBytes"])
                log.debug(ds["Stats"]["Usage"]["Zerto"]["Appliances"]["ProvisionedInBytes"])

                #metricsDictionary["datastore_health_status{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName'] + "\"}"] = ds["Health"]["Status"]
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
            vmapi = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            vmapi_json  = vmapi.json()
            #log.debug(vmapi_json)
            for vm in vmapi_json :
                metricsDictionary["vm_actualrpo{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["ActualRPO"]
                metricsDictionary["vm_throughput_in_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["ThroughputInMB"]
                metricsDictionary["vm_iops{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["IOPs"]
                metricsDictionary["vm_journal_hard_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["JournalHardLimit"]["LimitValue"]
                metricsDictionary["vm_journal_warning_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["JournalWarningThreshold"]["LimitValue"]
                metricsDictionary["vm_journal_used_storage_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["JournalUsedStorageMb"]
                metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["OutgoingBandWidthInMbps"]
                metricsDictionary["vm_used_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["UsedStorageInMB"]
                metricsDictionary["vm_provisioned_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["ProvisionedStorageInMB"]
                metricsDictionary["vm_status{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["Status"]
                metricsDictionary["vm_substatus{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + vm['VmName'] + "\",VmRecoveryVRA=\"" + vm["RecoveryHostName"] + "\",VmPriority=\"" + str(vm['Priority']) + "\"}"] = vm["SubStatus"]

            ## Volumes API for Scratch Volumes
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/volumes?volumeType=scratch"
            volapi = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
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

            ## Volumes API for Journal Volumes
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/volumes?volumeType=journal"
            volapi = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            volapi_json  = volapi.json()

            if(bool(volapi_json)):
                for volume in volapi_json :
                    #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                    # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                    metrickey = "vm_journal_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]

                    metrickey = "vm_journal_volume_provisioned_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["ProvisionedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["ProvisionedInBytes"]
                    
                    metrickey = "vm_journal_volume_count{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + 1
                    else:
                        metricsDictionary[metrickey] = 1
                    

            ### VRA API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vras/"
            service = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            vra_json  = service.json()
            log.debug(vra_json)
            for vra in vra_json :
                metricsDictionary["vra_memory_in_GB{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["MemoryInGB"]
                metricsDictionary["vra_vcpu_count{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["NumOfCpus"]
                metricsDictionary["vra_protected_vms{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["ProtectedCounters"]["Vms"]
                metricsDictionary["vra_protected_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["ProtectedCounters"]["Vpgs"]
                metricsDictionary["vra_protected_volumes{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["ProtectedCounters"]["Volumes"]
                metricsDictionary["vra_recovery_vms{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["RecoveryCounters"]["Vms"]
                metricsDictionary["vra_recovery_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["RecoveryCounters"]["Vpgs"]
                metricsDictionary["vra_recovery_volumes{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["RecoveryCounters"]["Volumes"]
                metricsDictionary["vra_self_protected_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion'] + "\"}"] = vra["SelfProtectedVpgs"]

            ## Write metrics to a human readable metrics.txt file as well as a metrics file that is easy to get in prometheus
            file_object = open('metrics', 'w')
            txt_object = open('metrics.txt', 'w')
            for item in metricsDictionary :
                file_object.write(item)
                file_object.write(" ")
                file_object.write(str(metricsDictionary[item]))
                file_object.write("\n")
                txt_object.write(item)
                txt_object.write(" ")
                txt_object.write(str(metricsDictionary[item]))
                txt_object.write("\n")
            
            file_object.close()
            txt_object.close()

            # This function will get data every 10 seconds
            log.debug("Starting Sleep for " + str(scrape_speed) + " seconds")
            time.sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            time.sleep(1)

def ThreadProbe():
    log.debug("Thread Probe Started")
    metricsDictionary = {}

    if auth_thread.is_alive():
        metricsDictionary["exporter_thread_status{thread=\"" + "AuthHandler" + "\"}"] = 1
    else:
        metricsDictionary["exporter_thread_status{thread=\"" + "AuthHandler" + "\"}"] = 0

    if data_thread.is_alive():
        metricsDictionary["exporter_thread_status{thread=\"" + "DataStats" + "\"}"] = 1
    else:
        metricsDictionary["exporter_thread_status{thread=\"" + "DataStats" + "\"}"] = 0

    if stats_thread.is_alive():
        metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats" + "\"}"] = 1
    else:
        metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats" + "\"}"] = 0

    file_object = open('threads', 'w')
    txt_object = open('threads.txt', 'w')
    for item in metricsDictionary :
        file_object.write(item)
        file_object.write(" ")
        file_object.write(str(metricsDictionary[item]))
        file_object.write("\n")
        txt_object.write(item)
        txt_object.write(" ")
        txt_object.write(str(metricsDictionary[item]))
        txt_object.write("\n")
    
    file_object.close()
    txt_object.close()
    sleep(30)

#----------------run http server on port 9999-----------------
def WebServer():
    log.info("Web Server Started")
    PORT = 9999

    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        log.info("Webserver running on port ", PORT)
        httpd.serve_forever()

def start_thread(target_func):
    # start a new thread
    thread = threading.Thread(target=target_func)
    thread.start()
    # return the thread object
    return thread

# start the threads
probe_thread = start_thread(ThreadProbe)
auth_thread = start_thread(ZvmAuthHandler)
data_thread = start_thread(GetDataFunc)
stats_thread = start_thread(GetStatsFunc)
webserver_thread = start_thread(WebServer)

print("Probe thread: " + str(probe_thread))
print("Auth thread: " + str(auth_thread))
print("Data thread: " + str(data_thread))
print("Stats thread: " + str(stats_thread))
print("Webserver thread: " + str(webserver_thread))

# loop indefinitely
while True:
    # check if any thread has crashed
    if not probe_thread.is_alive():
        # restart the thread
        log.error("Probe Thread Died - Restarting")
        probe_thread = start_thread(ThreadProbe)
    if not auth_thread.is_alive():
        # restart the thread
        log.error("Authentication Thread Died - Restarting")
        auth_thread = start_thread(ZvmAuthHandler)
    if not data_thread.is_alive():
        # restart the thread
        log.error("Data Thread Died - Restarting")
        data_thread = start_thread(GetDataFunc)
    if not stats_thread.is_alive():
        # restart the thread
        log.error("Stats Thread Died - Restarting")
        stats_thread = start_thread(GetStatsFunc)
    if not webserver_thread.is_alive():
        # restart the thread
        log.error("Webserver Thread Died - Restarting")
        webserver_thread = start_thread(WebServer)
    sleep(api_timeout)