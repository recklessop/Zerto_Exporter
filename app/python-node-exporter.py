import requests
import http.server
import socketserver
import os
import ssl
import logging
from logging.handlers import RotatingFileHandler
import threading
import socket
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from time import sleep, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict
from tinydb import TinyDB, Query
from tinydbstorage.storage import MemoryStorage
from version import VERSION
from vmware.vcenter import vcsite
from zvma10.zvma import zvmsite
from posthog import Posthog
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

global start_time
start_time = time()

"""
Variables: Normally these are imported from the Docker Container, but alternative values can be modified if running the script manually
"""

callhomestats = os.getenv("CALL_HOME_STATS", 'True').lower() in ('false', '0', 'f')
verifySSL = os.getenv("VERIFY_SSL", 'False').lower() in ('true', '1', 't')
zvm_url = os.environ.get('ZVM_HOST', '192.168.50.60')
zvm_port = os.environ.get('ZVM_PORT', '443')
client_id = os.environ.get('CLIENT_ID', 'api-script')
client_secret = os.environ.get('CLIENT_SECRET', 'fcYMFuA5TkIUwp6b3hDUxim0f32z8erk')
scrape_speed = int(os.environ.get('SCRAPE_SPEED', 30))
api_timeout = int(os.environ.get('API_TIMEOUT', 5))
LOGLEVEL = os.environ.get('LOGLEVEL', 'DEBUG').upper()
DISABLE_STATS = os.environ.get('DISABLE_STATS', 'FALSE').upper()
version = str(VERSION)
vcenter_host = os.environ.get('VCENTER_HOST', '192.168.50.50')
vcenter_user = os.environ.get('VCENTER_USER', 'administrator@vsphere.local')
vcenter_pwd = os.environ.get('VCENTER_PASSWORD', 'Zertodata987!')

# Thread which gets VM level encryption statistics from ZVM API

def GetStatsFunc(zvm_instance):
    tempdb = TinyDB(storage=MemoryStorage) # ('./db.json')   used for storing db on disk for debugging
    dbvm = Query()
    dbvpg = Query()
    zvm = zvm_instance
    while (True) :
        global siteId
        global siteName

        if (zvm.is_authenticated()):
            log.debug("Stats Collector Loop Running")
            
            metricsDictionary = {}
            
            ## Statistics API
            statsapi_json = None
            statsapi_json  = zvm.vms_statistics()
            log.debug(statsapi_json)
            vms_encryption_metrics = zvm.encryptiondetection_metrics_vms()

            if statsapi_json is not None:
                for vm in statsapi_json:
                    vmsiteinfo = zvm.vm(vmidentifier=vm['VmIdentifier'], vpgidentifier=vm['VpgIdentifier'])
                    if vmsiteinfo['ProtectedSite']['identifier'] == zvm.site_id:
                        log.debug(f"VM is protected at this site - {vm['VmIdentifier']}")
                        oldvmdata = dict()
                        if 'EncryptionMetrics' not in vm:
                            vm['EncryptionMetrics'] = {}
                        vm['VmName'] = None

                        CurrentIops                       = 0
                        CurrentWriteCounterInMBs          = 0
                        CurrentSyncCounterInMBs           = 0
                        CurrentNetworkTrafficCounterInMBs = 0
                        CurrentEncryptedLBs               = 0
                        CurrentUnencryptedLBs             = 0
                        CurrentTotalLBs                   = 0
                        CurrentPercentEncrypted           = 0
                        CurrentTrendChangeLevel           = 0
                        VMName                            = "NA"

                        for vmem in vms_encryption_metrics:
                            if vmem['Link']['identifier'] == vm['VmIdentifier']:
                                log.debug(f"Aligning VM Stats and Encryption Metrics for {vm['VmIdentifier']} - {vmem['Link']['name']}")
                                #print(f"Aligning VM Stats and Encryption Metrics for {vm['VmIdentifier']} - {vmem['Link']['name']}")
                                vm['EncryptionMetrics']['EncryptedData'] = vmem['EncryptionMetrics']['EncryptedData']
                                vm['EncryptionMetrics']['NonEncryptedData'] = vmem['EncryptionMetrics']['NonEncryptedData']
                                vm['EncryptionMetrics']['TrendChangeLevel'] = vmem['EncryptionMetrics']['TrendChangeLevel']
                                vm['VmName'] = vmem['Link']['name']

                        log.info("Checking TempDB for VM " + vm['VmIdentifier'] + " in VPG " + vm['VpgIdentifier'])
                        oldvmdata = tempdb.search(dbvm.VmIdentifier == vm['VmIdentifier'] and dbvpg.VpgIdentifier == vm['VpgIdentifier'])
                        if (oldvmdata):
                            log.info(vm['VmIdentifier'] + " Record Found, Updating DB")
                            log.debug(oldvmdata[0])
                            log.debug(tempdb.update(vm, dbvm.VmIdentifier == vm['VmIdentifier'] and dbvpg.VpgIdentifier == vm['VpgIdentifier']))

                            log.debug("!@!@!@!@!@  Stats  !@!@!@!@!@")
                            VMName                            = oldvmdata[0]['VmName']
                            log.debug("Current VM " + str(VMName))
                            CurrentIops                       = abs(vm['IoOperationsCounter'] - oldvmdata[0]['IoOperationsCounter'])
                            log.debug("CurrentIops " + str(CurrentIops))
                            CurrentSyncCounterInMBs           = abs(vm['SyncCounterInMBs'] - oldvmdata[0]['SyncCounterInMBs'])
                            log.debug("CurrentSyncCounterInMBs " + str(CurrentSyncCounterInMBs))
                            CurrentNetworkTrafficCounterInMBs = abs(vm['NetworkTrafficCounterInMBs'] - oldvmdata[0]['NetworkTrafficCounterInMBs'])
                            log.debug("CurrentNetworkTrafficCounterInMBs " + str(CurrentNetworkTrafficCounterInMBs))
                            CurrentWriteCounterInMBs = abs(vm['WriteCounterInMBs'] - oldvmdata[0]['WriteCounterInMBs'])
                            log.debug("CurrentWriteCounterInMBs " + str(CurrentWriteCounterInMBs))
                            CurrentEncryptedLBs               = abs(vm['EncryptionMetrics']['EncryptedData'] - oldvmdata[0]['EncryptionMetrics']['EncryptedData'])
                            log.debug("CurrentEncryptedLBs " + str(CurrentEncryptedLBs))
                            CurrentUnencryptedLBs             = abs(vm['EncryptionMetrics']['NonEncryptedData'] - oldvmdata[0]['EncryptionMetrics']['NonEncryptedData'])
                            log.debug("CurrentUnencryptedLBs " + str(CurrentUnencryptedLBs))
                            CurrentTrendChangeLevel             = abs(vm['EncryptionMetrics']['TrendChangeLevel'] - oldvmdata[0]['EncryptionMetrics']['TrendChangeLevel'])
                            log.debug("CurrentTrendChangeLevel " + str(CurrentTrendChangeLevel))
                            CurrentTotalLBs                   = abs(CurrentEncryptedLBs + CurrentUnencryptedLBs)
                            log.debug("CurrentTotalLBs " + str(CurrentTotalLBs))
                            if CurrentTotalLBs != 0:
                                CurrentPercentEncrypted       = ((CurrentEncryptedLBs / CurrentTotalLBs) * 100)
                            else:
                                CurrentPercentEncrypted       = 0
                            log.debug("CurrentPercentEncrypted " + str(CurrentPercentEncrypted))
                        else:
                            log.info(f"{vm['VmIdentifier']} - {vm['VmName']} -  No Record Found, Inserting into DB")
                            #insert original VM record to tempdb
                            log.debug(tempdb.insert(vm))

                        # Store Calculated Metrics
                        metricsDictionary["vm_IoOperationsCounter{VpgIdentifier=\"" + str(vm['VpgIdentifier']) + "\",VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + str(siteId) + "\",SiteName=\"" + str(siteName) + "\"}"] = CurrentIops
                        metricsDictionary["vm_WriteCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentWriteCounterInMBs
                        metricsDictionary["vm_SyncCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentSyncCounterInMBs
                        metricsDictionary["vm_NetworkTrafficCounterInMBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentNetworkTrafficCounterInMBs
                        metricsDictionary["vm_EncryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentEncryptedLBs
                        metricsDictionary["vm_UnencryptedDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentUnencryptedLBs
                        metricsDictionary["vm_TotalDataInLBs{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentTotalLBs
                        metricsDictionary["vm_PercentEncrypted{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentPercentEncrypted
                        metricsDictionary["vm_TrendChangeLevel{VpgIdentifier=\"" + vm['VpgIdentifier'] + "\",VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = CurrentTrendChangeLevel
                    else:
                        log.debug(f"VM is only recovering to this site, skipping metrics - {vm['VmIdentifier']}")
                        #print(f"VM is only recovering to this site, skipping metrics - {vm['VmIdentifier']}")
            else:
                log.debug("No VMS in Stats API")

            

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
def GetDataFunc(zvm_instance):
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    zvm = zvm_instance
    while (True) :
        global siteId
        global siteName

        if (zvm.is_authenticated()):
            log.info("Data Collector Loop Running")
            metricsDictionary = {}

            ### VPGs API
            vpg_json = None
            vpg_json  = zvm.vpgs()
            if(vpg_json is not None):
                log.debug("Got VPG JSON")
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
            else:
                log.debug("No VPGs Found")

            ### Datastores APIs
            ds_json = None
            ds_json  = zvm.datastores()
            if(ds_json is not None):
                log.debug("Got Datastores API")
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
            else:
                log.debug("No Datastores Found")

            ## VMs API
            log.debug("Getting VMs API")
            scratch_vols = None
            scratch_vols  = zvm.vms()
            if(scratch_vols is not None):
                log.debug("Got VMs API")
                for vm in scratch_vols:
                    log.debug("Processing VM: " + str(vm['VmName']))
                    log.debug("Checking VM " + vm['VmIdentifier'] + " on Protected Site " + vm['ProtectedSite']['identifier'] + " against " + siteId)

                    if siteId == vm['ProtectedSite']['identifier']:
                        log.debug("Found VM " + vm['VmIdentifier'] + " on Protected Site")

                        if not isinstance(vm["ActualRPO"], int):
                            vm["ActualRPO"] = -1
                        metricsDictionary["vm_actualrpo{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["ActualRPO"]
                        metricsDictionary["vm_throughput_in_mb{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["ThroughputInMB"]
                        metricsDictionary["vm_iops{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["IOPs"]
                        metricsDictionary["vm_journal_hard_limit{VmIdentifier=\"" + str(vm['VmIdentifier']) + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + str(siteName) + "\"}"] = vm["JournalHardLimit"]["LimitValue"]
                        metricsDictionary["vm_journal_warning_limit{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["JournalWarningThreshold"]["LimitValue"]
                        metricsDictionary["vm_journal_used_storage_mb{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["JournalUsedStorageMb"]
                        metricsDictionary["vm_outgoing_bandwidth_in_mbps{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["OutgoingBandWidthInMbps"]
                        metricsDictionary["vm_used_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["UsedStorageInMB"]
                        metricsDictionary["vm_provisioned_storage_in_MB{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["ProvisionedStorageInMB"]
                        metricsDictionary["vm_status{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["Status"]
                        metricsDictionary["vm_substatus{VmIdentifier=\"" + vm['VmIdentifier'] + "\",VmName=\"" + str(vm['VmName']) + "\",VmRecoveryVRA=\"" + str(vm["RecoveryHostName"]) + "\",VmPriority=\"" + str(vm['Priority'])  + "\",SiteIdentifier=\"" + str(siteId) + "\",VpgName=\"" + str(vm['VpgName']) + "\",SiteName=\"" + siteName + "\"}"] = vm["SubStatus"]
                        log.debug("Processed VM: " + str(vm['VmName']))

                    else:
                        log.debug("VM " + vm['VmIdentifier'] + " is protected to this site")
            else:
                log.debug("No VMs Found")


            ## Volumes API for Scratch Volumes
            log.debug("Getting Scratch Volumes")
            scratch_vols = None
            scratch_vols = zvm.volumes(volumetype="scratch")

            if(scratch_vols is not None):
                log.debug("Got Scratch Volumes API")
                for volume in scratch_vols:
                    #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                    # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                    metrickey = "scratch_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\",VpgName=\"" + str(volume['Vpg']['Name']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]
                    percentage_used = (volume["Size"]["UsedInBytes"] / volume["Size"]["ProvisionedInBytes"] * 100)
                    percentage_used = round(percentage_used, 1)
                    #metricsDictionary["scratch_volume_percentage_used{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = percentage_used
            else:
                log.debug("No Scratch Volumes Found")

            ## Volumes API for Journal Volumes
            log.debug("Getting Journal Volumes")
            journal_vols = None
            journal_vols = zvm.volumes(volumetype="journal")

            if(journal_vols is not None):
                log.debug("Journal Volumes Exist")
                for volume in journal_vols :
                    log.debug("Journal Volume: " + volume['ProtectedVm']['Name'] + " Calculating total size...")
                    #metricsDictionary["scratch_volume_provisioned_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\"}"] = volume["Size"]["ProvisionedInBytes"]
                    # Determine the key for a given VM, then see if the key is already in the dictionary, if it is add the next disk to the total. If not, create a new key.
                    metrickey = "vm_journal_volume_size_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\",VpgName=\"" + str(volume['Vpg']['Name']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["UsedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["UsedInBytes"]

                    metrickey = "vm_journal_volume_provisioned_in_bytes{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\",VpgName=\"" + str(volume['Vpg']['Name']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + volume["Size"]["ProvisionedInBytes"]
                    else:
                        metricsDictionary[metrickey] = volume["Size"]["ProvisionedInBytes"]
                    
                    metrickey = "vm_journal_volume_count{ProtectedVm=\"" + volume['ProtectedVm']['Name'] + "\", ProtectedVmIdentifier=\"" + volume['ProtectedVm']['Identifier'] + "\", OwningVRA=\"" + volume['OwningVm']['Name'] + "\",VpgName=\"" + str(volume['Vpg']['Name']) + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"
                    if (metrickey in metricsDictionary):
                        metricsDictionary[metrickey] = metricsDictionary[metrickey] + 1
                    else:
                        metricsDictionary[metrickey] = 1
            else:
                log.debug("No Journal Volumes Exist")
                    
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
def GetVraMetrics(zvm_instance):
    log.debug("GetVraMetrics thread started")
    try:

        metricsDictionary = {}
        zvm = zvm_instance
        while True:
            vra_names = []
            vras = []
            global siteId
            global siteName

            log.debug("Checking Token in VRA CPU MEM Collector")
            if (zvm.is_authenticated()):
                log.info("VRA CPU MEM Collector Running")

                ### VRA API
                vras_json = None
                vras_json = zvm.vras()
                log.debug(vras_json)
                        
                if (vras_json is not None):
                    log.debug("VRA names: %s", vras_json)
                    log.debug(type(vras))
                    for vra in vras_json :     
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
                        log.info(f"vCenter info: T/F = {is_vcenter_set} Host: {vcenter_host} u: {vcenter_user}")

                        # get the CPU and memory usage for each VRA
                        if is_vcenter_set:
                            log.debug(f"vCenter Info Is Valid... Trying to get CPU and Memory usage for VRAs")
                            try:
                                log.debug("Trying to get stats from vc module")
                                vradata = vc_connection.get_cpu_mem_used(vra['VraName'])
                            
                                # get the CPU usage and memory usage for the VM
                                cpu_usage_mhz = vradata[0]
                                memory_usage_mb = vradata[1]

                                # print the CPU and memory usage for the VM
                                log.debug(f"VRA {vra['VraName']}) has CPU usage of {cpu_usage_mhz} MHz and memory usage of {memory_usage_mb} MB")
                                metricsDictionary["vra_cpu_usage_mhz{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = cpu_usage_mhz
                                metricsDictionary["vra_memory_usage_mb{VraIdentifierStr=\"" + vra['VraIdentifierStr'] + "\",VraName=\"" + vra['VraName'] + "\",VraVersion=\"" + vra['VraVersion'] + "\",HostVersion=\"" + vra['HostVersion']  + "\",SiteIdentifier=\"" + siteId + "\",SiteName=\"" + siteName + "\"}"] = memory_usage_mb
                            except:
                                log.info(f"No VM found with name {vra['VraName']}")
                else:
                    log.debug("No VRAs Found")
                
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
                log.debug("Starting Sleep for " + str(int(scrape_speed *2)) + " seconds")
                sleep(scrape_speed * 2)
            else:
                log.debug("Waiting 1 second for Auth Token")
                sleep(1)
    except Exception as e:
        log.error(f"Error in GetVraMetrics: {e}")

# function which monitors the threads and restarts them if they die
def ThreadProbe():
    global container_id
    while True:
        log.debug("Thread Probe Started")
        metricsDictionary = {}

        uptime = round((time() - start_time) / 60, 1)
        metricsDictionary["exporter_uptime{ExporterInstance=\"" + container_id + "\"}"] = uptime
        if data_thread.is_alive():
            log.debug("Data Thread Is Alive")
            metricsDictionary["exporter_thread_status{thread=\"" + "DataStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            log.debug("Data Thread Is NOT Alive")
            metricsDictionary["exporter_thread_status{thread=\"" + "DataStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        if stats_thread.is_alive():
            log.debug("Stats Thread Is Alive")
            metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            log.debug("Stats Thread Is NOT Alive")
            metricsDictionary["exporter_thread_status{thread=\"" + "EncryptionStats"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 0

        if vra_metrics_thread.is_alive():
            log.debug("VRA Metrics Thread Is Alive")
            metricsDictionary["exporter_thread_status{thread=\"" + "VraMetrics"  + "\",ExporterInstance=\"" + container_id + "\"}"] = 1
        else:
            log.debug("VRA Metrics Thread Is NOT Alive")
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
    log.debug(f"Starting thread for {target_func.__name__}")
    thread = threading.Thread(target=target_func)
    thread.daemon = True
    thread.start()
    log.debug(f"Thread {target_func.__name__} started")
    return thread

"""
Main Program Logic
"""

# Get the hostname of the machine
container_id = str(socket.gethostname())

#set log line format including container_id
log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")
log_handler = RotatingFileHandler(filename=f"./logs/Log-{container_id}.log", maxBytes=1024*1024*100, backupCount=5)
log_handler.setFormatter(log_formatter)
log = logging.getLogger("Node-Exporter")
log.setLevel(LOGLEVEL)
log.addHandler(log_handler)
log.info(f"Zerto-Node-Exporter - Version {version}")
log.info(f"Log Level: {LOGLEVEL}")
log.debug("Running with Variables:\nVerify SSL: " + str(verifySSL) + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

# Initialize zvmsite instance
zvm_instance = zvmsite(
    host=zvm_url, 
    port=zvm_port, 
    client_id=client_id, 
    client_secret=client_secret,
    grant_type="client_credentials",
    loglevel=LOGLEVEL,
    logger=log,
    stats=DISABLE_STATS
)
# Start the zvmsite authentication thread
zvm_instance.connect()

"""
Global Variables used by the program
"""
local_site_info = None
siteId = None
siteName = None

while(siteId is None):
    if zvm_instance.is_authenticated():
        sleep(2)
        log.debug("Trying Set Global Vars")
        siteId = zvm_instance.site_id
        siteName = zvm_instance.site_name

lastStats = CaseInsensitiveDict()

# Check if vCenter is set, if not disable VRA metrics
is_vcenter_set = True
if vcenter_host == "vcenter.local":
    log.error("vCenter Host not set. Please set the environment variable VCENTER_HOST, turning off VRA CPU and Memory metrics")
    is_vcenter_set = False
log.debug("vCenter data collection is enabled")
vc_connection = vcsite(vcenter_host, vcenter_user, vcenter_pwd, loglevel="debug", logger=log)

# Starting threads
vra_metrics_thread = start_thread(lambda: GetVraMetrics(zvm_instance))
data_thread = start_thread(lambda: GetDataFunc(zvm_instance))
stats_thread = start_thread(lambda: GetStatsFunc(zvm_instance))
log.debug("Starting VRA Metrics")

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
    if not data_thread.is_alive():
        # restart the thread
        log.error("Data Thread Died - Restarting")
        data_thread = start_thread(GetDataFunc(zvm_instance))
    if not stats_thread.is_alive():
        # restart the thread
        log.error("Stats Thread Died - Restarting")
        stats_thread = start_thread(lambda: GetStatsFunc(zvm_instance))
    if not vra_metrics_thread.is_alive():
        # restart the thread
        log.error("VRA Metrics Thread Died - Restarting")
        vra_metrics_thread = start_thread(GetVraMetrics(zvm_instance))
    if not webserver_thread.is_alive():
        # restart the thread
        log.error("Webserver Thread Died - Restarting")
        webserver_thread = start_thread(WebServer)
    sleep(api_timeout)