import requests
import http.server
import socketserver
import os
import ssl
import logging
import threading
import socket
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from time import sleep
from logging.handlers import RotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict
from tinydb import TinyDB, Query
from tinydbstorage.storage import MemoryStorage
from version import VERSION

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
verifySSL = os.getenv("VERIFY_SSL", 'False').lower() in ('true', '1', 't')
zvm_url = os.environ.get('ZVM_HOST', '192.168.50.60')
zvm_port = os.environ.get('ZVM_PORT', '443')
client_id = os.environ.get('CLIENT_ID', 'api-script')
client_secret = os.environ.get('CLIENT_SECRET', 'js51tDM8oappYUGRJBhF7bcsedNoHA5j')
scrape_speed = int(os.environ.get('SCRAPE_SPEED', 30))
api_timeout = int(os.environ.get('API_TIMEOUT', 5))
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
version = str(VERSION)
vcenter_host = os.environ.get('VCENTER_HOST', 'vcenter.local')
vcenter_user = os.environ.get('VCENTER_USER', 'administrator@vsphere.local')
vcenter_pwd = os.environ.get('VCENTER_PASSWORD', 'supersecret')

# Get the hostname of the machine
container_id = str(socket.gethostname())

#set log line format including container_id
log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")

log_handler = RotatingFileHandler(filename=f"./logs/Log-Main-{container_id}.log", maxBytes=1024*1024*100, backupCount=5)
log_handler.setFormatter(log_formatter)

log = logging.getLogger("Node-Exporter")
log.setLevel(LOGLEVEL)
log.addHandler(log_handler)
log.info(f"Zerto-Node-Exporter - Version {version}")
log.info(f"Log Level: {LOGLEVEL}")
log.debug("Running with Variables:\nVerify SSL: " + str(verifySSL) + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

# Global Variables
token = ""
siteId = "NotSet"
siteName = "NotSet"
lastStats = CaseInsensitiveDict()

# Check if vCenter is set, if not disable VRA metrics
is_vcenter_set = True
if vcenter_host == "vcenter.local":
    log.error("vCenter Host not set. Please set the environment variable VCENTER_HOST, turning off VRA CPU and Memory metrics")
    is_vcenter_set = False
log.debug("vCenter data collection is enabled")

# Authentication Thread which handles authentication and token refresh for ZVM API
def ZvmAuthHandler():
    log.debug("ZVMAuthHandler Thread Started")
    expiresIn = 0
    global token
    global siteId
    global siteName
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
                sleep(delay)
                continue
            else:
                retries = 0
            
            responseJSON = response.json()
            if 'access_token' not in responseJSON or 'expires_in' not in responseJSON:
                log.error("Authentication response does not contain expected keys")
                delay = 2 ** retries
                sleep(delay)
                retries += 1
                continue
            
            token = str(responseJSON.get('access_token'))
            expiresIn = int(responseJSON.get('expires_in'))
            log.info("Authentication successful. Token expires in " + str(expiresIn) + " seconds")

            if response.status_code != 200:
                log.error("Authentication request failed with status code " + str(response.status_code))
                delay = 2 ** retries
                sleep(delay)
                retries += 1
                continue

            # Get Site ID and Name
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/localsite"
            delay = 0
            try:
                log.debug("Getting Site ID and Name")
                h2 = CaseInsensitiveDict()
                h2["Accept"] = "application/json"
                h2["Authorization"] = "Bearer " + token
                response = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                retries += 1
                delay = 2 ** retries
                log.error("Error while sending authentication request: " + str(e) + ". Retrying in " + str(delay) + " seconds")
                sleep(delay)
                continue
            else:
                retries = 0
            
            responseJSON = response.json()
            log.debug(responseJSON)
            if 'SiteIdentifier' not in responseJSON or 'SiteName' not in responseJSON:
                log.error("LocalSite API response does not contain expected keys")
                delay = 2 ** retries
                sleep(delay)
                retries += 1
                continue
            else:
                siteId = str(responseJSON.get('SiteIdentifier'))
                siteName = str(responseJSON.get('SiteName'))
                log.info("Site ID: " + siteId + " Site Name: " + siteName)
                
        expiresIn -= 10 + delay
        log.debug("Token Expires in " + str(expiresIn) + " seconds")
        sleep(10)


# Thread which gets VM level encryption statistics from ZVM API
def GetStatsFunc():
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    while (True) :
        global token
        global siteId
        global siteName

        if (token != ""):
            log.info("Got Auth Token!")
            log.debug("token: " + str(token))
            log.debug("Stats Collector Loop Running")
            
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

                log.info("Checking TempDB for VM " + vm['VmIdentifier'])
                if (oldvmdata):
                    log.info(vm['VmIdentifier'] + " Record Found")
                    log.debug(oldvmdata[0])
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
                    log.info(vm['VmIdentifier'] + " No Record Found, Inserting into DB")
                    #insert original VM record to tempdb
                    log.debug(tempdb.insert(vm))

                    # update database with VM name, for easier display in Grafana Legends
                    uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/" + vm['VmIdentifier']
                    try:
                        vapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                        vapi_json  = vapi.json()
                    except Exception as e:
                        log.error("Error while sending api request: " + str(e))
                        VMName = "Unknown"
                    else:
                        log.debug("vapi_json: " + str(vapi_json))
                        tempdb.update({'VmName': vapi_json['VmName']}, dbvm.VmIdentifier == vm['VmIdentifier'])
                        log.info("Added to temp vm db" + vm['VmIdentifier'] + " - " + vapi_json['VmName'])
                        VMName = vapi_json['VmName']

                    # Store Calculated Metrics
                    metricsDictionary["vm_IoOperationsCounter{VpgIdentifier=\"" + str(vm['VpgIdentifier']) + "\",VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(VMName)  + "\",SiteIdentifier=\"" + str(siteId) + "\",SiteName=\"" + str(siteName) + "\"}"] = CurrentIops
                    metricsDictionary["vm_WriteCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentWriteCounterInMBs
                    metricsDictionary["vm_SyncCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentSyncCounterInMBs
                    metricsDictionary["vm_NetworkTrafficCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentNetworkTrafficCounterInMBs
                    metricsDictionary["vm_EncryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentEncryptedLBs
                    metricsDictionary["vm_UnencryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentUnencryptedLBs
                    metricsDictionary["vm_TotalDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentTotalLBs
                    metricsDictionary["vm_PercentEncrypted{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + VMName  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentPercentEncrypted

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
            sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            sleep(1)

# Function which retrieves stats from various ZVM APIs and stores them in a metrics file
def GetDataFunc():
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    while (True) :
        global token
        global siteId
        global siteName

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
                metricsDictionary["vpg_storage_used_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["UsedStorageInMB"]
                metricsDictionary["vpg_actual_rpo{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["ActualRPO"]
                metricsDictionary["vpg_throughput_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["ThroughputInMB"]
                metricsDictionary["vpg_iops{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["IOPs"]
                metricsDictionary["vpg_provisioned_storage_in_mb{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["ProvisionedStorageInMB"]
                metricsDictionary["vpg_vms_count{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["VmsCount"]
                metricsDictionary["vpg_configured_rpo_seconds{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["ConfiguredRpoSeconds"]
                metricsDictionary["vpg_actual_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["HistoryStatusApi"]["ActualHistoryInMinutes"]
                metricsDictionary["vpg_configured_history_in_minutes{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"]
                metricsDictionary["vpg_failsafe_history_in_minutes_actual{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["FailSafeHistory"]["ActualFailSafeHistory"]
                metricsDictionary["vpg_failsafe_history_in_minutes_configured{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["FailSafeHistory"]["ConfiguredFailSafeHistory"]
                metricsDictionary["vpg_status{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["Status"]
                metricsDictionary["vpg_substatus{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["SubStatus"]
                metricsDictionary["vpg_alert_status{VpgIdentifier=\"" + vpg['VpgIdentifier'] + "\",VpgName=\"" + vpg['VpgName'] + "\",VpgPriority=\"" + str(vpg['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vpg["AlertStatus"]

            ### Datastores APIs
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/datastores/"
            service = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            ds_json  = service.json()
            #log.debug(ds_json)
            for ds in ds_json :

                log.debug(f"Processing {ds['DatastoreName']}")

                metricsDictionary["datastore_vras{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["NumVRAs"]
                metricsDictionary["datastore_incoming_vms{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["NumIncomingVMs"]
                metricsDictionary["datastore_outgoing_vms{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["NumOutgoingVMs"]
                metricsDictionary["datastore_usage_capacityinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["CapacityInBytes"]
                metricsDictionary["datastore_usage_freeinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["FreeInBytes"]
                metricsDictionary["datastore_usage_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["UsedInBytes"]
                metricsDictionary["datastore_usage_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Datastore"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_protected_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Protected"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_protected_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Protected"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_recovery_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Recovery"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_recovery_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Recovery"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_journal_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Journal"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_journal_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Journal"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_scratch_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Scratch"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_scratch_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Scratch"]["ProvisionedInBytes"]
                metricsDictionary["datastore_usage_zerto_appliances_usedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Appliances"]["UsedInBytes"]
                metricsDictionary["datastore_usage_zerto_appliances_provisionedinbytes{datastoreIdentifier=\"" + ds['DatastoreIdentifier'] + "\",DatastoreName=\"" + ds['DatastoreName']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = ds["Stats"]["Usage"]["Zerto"]["Appliances"]["ProvisionedInBytes"]

            ## VMs API
            log.debug("Getting VMs API")
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/"

            vmapi_json = {}
            try:
                vmapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                vmapi_json  = vmapi.json()
            except Exception as e:
                log.error("Error while sending api request: " + str(e))
                VMName = "Unknown"
                return

            log.debug("Got VMs API")
            log.debug(vmapi_json)
            for vm in vmapi_json :
                log.debug("Processing VM: " + str(vm['VmName']))
                log.debug("Checking VM " + vm['VmIdentifier'] + " on Protected Site " + vm['ProtectedSite']['identifier'] + " against " + siteId)

                if siteId == vm['ProtectedSite']['identifier']:
                    log.debug("Found VM " + vm['VmIdentifier'] + " on Protected Site")

                    if not isinstance(vm["ActualRPO"], int):
                        vm["ActualRPO"] = -1
                    metricsDictionary["vm_actualrpo{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["ActualRPO"]
                    metricsDictionary["vm_throughput_in_mb{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["ThroughputInMB"]
                    metricsDictionary["vm_iops{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["IOPs"]
                    metricsDictionary["vm_journal_hard_limit{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["JournalHardLimit"]["LimitValue"]
                    metricsDictionary["vm_journal_warning_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["JournalWarningThreshold"]["LimitValue"]
                    metricsDictionary["vm_journal_used_storage_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["JournalUsedStorageMb"]
                    metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["OutgoingBandWidthInMbps"]
                    metricsDictionary["vm_used_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["UsedStorageInMB"]
                    metricsDictionary["vm_provisioned_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["ProvisionedStorageInMB"]
                    metricsDictionary["vm_status{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["Status"]
                    metricsDictionary["vm_substatus{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vm["SubStatus"]
                    log.debug("Processed VM: " + str(vm['VmName']))

                else:
                    log.debug("VM " + vm['VmIdentifier'] + " is protected to this site")


            ## Volumes API for Scratch Volumes
            log.debug("Getting Scratch Volumes")
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/volumes?volumeType=scratch"

            volapi_json = {}
            try:
                volapi = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
                volapi_json  = volapi.json()
            except Exception as e:
                log.error("Error while sending api request: " + str(e))
                VMName = "Unknown"
                return

            log.debug("Got Scratch Volumes API")
            if(bool(volapi_json)):
                for volume in volapi_json :
                    #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                    # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                    metrickey = "scratch_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]
                    percentage_used = (volume["Size"]["UsedInBytes"] / volume["Size"]["ProvisionedInBytes"] * 100)
                    percentage_used = round(percentage_used, 1)
                    #metricsDictionary["scratch_volume_percentage_used{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = percentage_used

            ## Volumes API for Journal Volumes
            log.debug("Getting Journal Volumes")

            volapi_json = {}
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/volumes?volumeType=journal"            
            try:
                volapi = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
                volapi_json  = volapi.json()
            except Exception as e:
                log.error("Error while sending api request: " + str(e))
                VMName = "Unknown"
                return

            log.debug("Got Journal Volumes API")
            if(bool(volapi_json)):
                log.debug("Journal Volumes Exist")
                for volume in volapi_json :
                    log.debug("Journal Volume: " + volume['ProtectedVm']['Name'] + " Calculating total size...")
                    #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                    # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                    metrickey = "vm_journal_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]

                    metrickey = "vm_journal_volume_provisioned_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["ProvisionedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["ProvisionedInBytes"]
                    
                    metrickey = "vm_journal_volume_count{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + 1
                    else:
                        metricsDictionary[metrickey] = 1
                    
            ## Write metrics to a human readable metrics.txt file as well as a metrics file that is easy to get in prometheus
            log.debug("Writing metrics to file")
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
            log.debug("Metrics written to file")

            # This function will get data every 10 seconds
            log.debug("Starting Sleep for " + str(scrape_speed) + " seconds")
            sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            sleep(1)

# get VRA CPU and memory usage from vCenter Server
def GetVraMetrics():
    # set up API endpoint and headers
    log.debug("GetVraCpuMemory() called")
    metricsDictionary = {}
    while True:
        vra_names = []
        vras = []
        global token
        global siteId
        global siteName

        log.debug("Checking Token in VRA CPU MEM Collector")
        if (token != ""):
            log.debug("Auth Token Valid!")
            log.debug("token: " + str(token))
            log.info("VRA CPU MEM Collector Running")

            h2 = CaseInsensitiveDict()
            h2["Accept"] = "application/json"
            h2["Authorization"] = "Bearer " + token
            

            ### VRA API
            uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vras"

            # make API call to get list of VRAs
            try:
                response = requests.get(url=uri, timeout=api_timeout, headers=h2, verify=verifySSL)
            except Exception as e:
                log.error(f"Error connecting to {endpoint}: {e}")
                return
            else:
                log.debug("Response from GET /v1/vras: %s", response.text)
                # parse JSON response and get the name of each VRA
                
                if is_vcenter_set:
                    # Disable SSL certificate verification
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.verify_mode = ssl.CERT_NONE

                    # connect to vCenter Server
                    si = None
                    try:
                        si = SmartConnect(host=vcenter_host, user=vcenter_user, pwd=vcenter_pwd, sslContext=context)
                        log.debug("Connected to vCenter Server %s", vcenter_host)
                    except Exception as e:
                        log.error(f"Error connecting to vCenter Server: {e}")
                        return

                    
                    # get the root folder of the vCenter Server
                    content = si.RetrieveContent()
                    root_folder = content.rootFolder

                    # create a view for all VMs on the vCenter Server
                    view_manager = content.viewManager
                    vm_view = view_manager.CreateContainerView(root_folder, [vim.VirtualMachine], True)

                    
                    
                    vras = response.json()
                    
                log.debug("VRA names: %s", vras)
                log.debug(type(vras))
                for vra in vras :
                    #vra_names.append(vra['VraName'])
                    
                    # Gather other VRA Metrics from Zerto API into Metrics Diectionary
                    metricsDictionary["vra_memory_in_GB{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["MemoryInGB"]
                    metricsDictionary["vra_vcpu_count{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["NumOfCpus"]
                    metricsDictionary["vra_protected_vms{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["ProtectedCounters"]["Vms"]
                    metricsDictionary["vra_protected_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["ProtectedCounters"]["Vpgs"]
                    metricsDictionary["vra_protected_volumes{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["ProtectedCounters"]["Volumes"]
                    metricsDictionary["vra_recovery_vms{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["RecoveryCounters"]["Vms"]
                    metricsDictionary["vra_recovery_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["RecoveryCounters"]["Vpgs"]
                    metricsDictionary["vra_recovery_volumes{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["RecoveryCounters"]["Volumes"]
                    metricsDictionary["vra_self_protected_vpgs{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = vra["SelfProtectedVpgs"]

            
                    log.debug("VRA Name: %s", vra['VraName'])


                    # get the CPU and memory usage for each VRA
                    if is_vcenter_set:
                        vm = None
                        for vm_obj in vm_view.view:
                            if vm_obj.name == vra['VraName']:
                                vm = vm_obj
                                break
                                
                        if vm is not None:
                            log.debug("Found VRA VM in vCenter with name %s", vra['VraName'])
                            # get the CPU usage and memory usage for the VM
                            cpu_usage_mhz = vm.summary.quickStats.overallCpuUsage
                            memory_usage_mb = vm.summary.quickStats.guestMemoryUsage

                            # print the CPU and memory usage for the VM
                            log.info(f"VM {vm.name} (name: {vra['VraName']}) has CPU usage of {cpu_usage_mhz} MHz and memory usage of {memory_usage_mb} MB")
                            metricsDictionary["vra_cpu_usage_mhz{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = cpu_usage_mhz
                            metricsDictionary["vra_memory_usage_mb{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = memory_usage_mb
                        else:
                            log.info(f"No VM found with name {vra['VraName']}")

            # Disconnect from vCenter
            Disconnect(si)
            
            ## Write metrics to a human readable metrics.txt file as well as a metrics file that is easy to get in prometheus
            file_object = open('vrametrics', 'w')
            txt_object = open('vrametrics.txt', 'w')
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
            sleep(scrape_speed * 2)
        else:
            log.debug("Waiting 1 second for Auth Token")
            sleep(1)


# function which monitors the threads and restarts them if they die
def ThreadProbe():
    global container_id
    while True:
        log.debug("Thread Probe Started")
        metricsDictionary = {}

        log.debug("Is Auth Thread Alive")
        if auth_thread.is_alive():
            metricsDictionary["exporter_thread_status{thread=\"" + "AuthHandler"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            metricsDictionary["exporter_thread_status{thread=\"" + "AuthHandler"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        log.debug("Is Data Thread Alive")
        if data_thread.is_alive():
            metricsDictionary["exporter_thread_status{thread=\"" + "DataStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            metricsDictionary["exporter_thread_status{thread=\"" + "DataStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        log.debug("Is Stats Thread Alive")
        if stats_thread.is_alive():
            metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        log.debug("Is VRA Metrics Thread Alive")
        if vra_metrics_thread.is_alive():
            metricsDictionary["exporter_thread_status{thread=\"" + "VraMetrics"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            metricsDictionary["exporter_thread_status{thread=\"" + "VraMetrics"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        log.debug("Writing Probe data to files")
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

        log.debug("Trying to Close probe txt files")
        file_object.close()
        txt_object.close()

        log.debug("Probe Thread Going to Sleep")
        sleep(30)


#----------------run http server on port 9999-----------------
def WebServer():
    log.info("Web Server Started")
    PORT = 9999

    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        log.info(f"Webserver running on port {PORT}")
        httpd.serve_forever()

def start_thread(target_func):
    # start a new thread
    thread = threading.Thread(target=target_func)
    thread.start()
    # return the thread object
    return thread

# start the threads

auth_thread = start_thread(ZvmAuthHandler)
data_thread = start_thread(GetDataFunc)
stats_thread = start_thread(GetStatsFunc)
vra_metrics_thread = start_thread(GetVraMetrics)
webserver_thread = start_thread(WebServer)
probe_thread = start_thread(ThreadProbe)

# loop indefinitely
while True:
    # check if any thread has crashed
    sleep(10)
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
    if not vra_metrics_thread.is_alive():
        # restart the thread
        log.error("VRA Metrics Thread Died - Restarting")
        vra_metrics_thread = start_thread(GetVraMetrics)
    if not webserver_thread.is_alive():
        # restart the thread
        log.error("Webserver Thread Died - Restarting")
        webserver_thread = start_thread(WebServer)
    sleep(api_timeout)