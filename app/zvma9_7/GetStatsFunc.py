
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict
from tinydb import TinyDB, Query
from tinydbstorage.storage import MemoryStorage
from logging.handlers import RotatingFileHandler

# Function to get VM Encryption Data from ZVMa version 9.7
def GetStatsFunc():
    tempdb = TinyDB(storage=MemoryStorage) # ('./db.json')   used for storing db on disk for debugging
    dbvm = Query()
    dbvpg = Query()
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

                oldvmdata = tempdb.search(dbvm.VmIdentifier == vm['VmIdentifier'] and dbvpg.VpgIdentifier == vm['VpgIdentifier'])

                log.info("Checking TempDB for VM " + vm['VmIdentifier'] + " in VPG " + vm['VpgIdentifier'])
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
                    uri = "https://" + zvm_url + ":" + zvm_port + "/v1/vms/" + vm['VmIdentifier'] +"?vpgIdentifier=" + vm['VpgIdentifier']
                    try:
                        vapi = requests.get(url=uri, timeout=3, headers=h2, verify=verifySSL)
                        vapi_json  = vapi.json()
                    except Exception as e:
                        log.error("Error while sending api request: " + str(e))
                        VMName = "Unknown"
                    else:
                        log.debug("vapi_json: " + str(vapi_json))
                        tempdb.update({'VmName': vapi_json['VmName']}, dbvm.VmIdentifier == vm['VmIdentifier'])
                        log.info("Added vm to tempdb " + vm['VmIdentifier'] + " - " + vapi_json['VmName'])
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