import requests
import os
import sys
import json
import logging
import threading
import socket
from time import sleep, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tinydb import TinyDB, Query
from tinydb.storages import MemoryStorage
from prometheus_client import Gauge, start_http_server
from version import VERSION
from vmware.vcenter import vcsite
from zvma10.zvma import zvmsite
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

global start_time
start_time = time()

"""
Variables: Normally these are imported from the Docker Container, but alternative values can be modified if running the script manually
"""

listen_port = int(os.getenv('LISTEN_PORT', 9999))
verifySSL = os.getenv("VERIFY_SSL", 'False').lower() in ('true', '1', 't')
zvm_url = os.environ.get('ZVM_HOST', '192.168.50.30')
zvm_port = os.environ.get('ZVM_PORT', '443')
zvm_username = os.environ.get('ZVM_USERNAME', 'admin')
zvm_password = os.environ.get('ZVM_PASSWORD', 'Zertodata987!')
client_id = os.environ.get('CLIENT_ID', 'zerto-client')
client_secret = os.environ.get('CLIENT_SECRET', 'fcYMFuA5TkIUwp6b3hDUxim0f32z8erk')
scrape_speed = int(os.environ.get('SCRAPE_SPEED', 30))
api_timeout = int(os.environ.get('API_TIMEOUT', 5))
LOGLEVEL = os.environ.get('LOGLEVEL', 'DEBUG').upper()
DISABLE_STATS = os.environ.get('DISABLE_STATS', 'FALSE').upper()
version = str(VERSION)
vcenter_host = os.environ.get('VCENTER_HOST', '192.168.50.20')
vcenter_user = os.environ.get('VCENTER_USER', 'administrator@vsphere.local')
vcenter_pwd = os.environ.get('VCENTER_PASSWORD', 'Zertodata987!')

# ---------------------------------------------------------------------------
# Prometheus Gauge definitions
# All metrics are served thread-safely at http://host:<LISTEN_PORT>/metrics
# ---------------------------------------------------------------------------

# Encryption / stats metrics (GetStatsFunc)
_STATS_LABELS = ['VpgIdentifier', 'VmIdentifier', 'VmName', 'SiteIdentifier', 'SiteName']
g_vm_iops_counter        = Gauge('vm_IoOperationsCounter',        'VM IO Operations Counter',             _STATS_LABELS)
g_vm_write_counter       = Gauge('vm_WriteCounterInMBs',          'VM Write Counter In MBs',              _STATS_LABELS)
g_vm_sync_counter        = Gauge('vm_SyncCounterInMBs',           'VM Sync Counter In MBs',               _STATS_LABELS)
g_vm_network_counter     = Gauge('vm_NetworkTrafficCounterInMBs', 'VM Network Traffic Counter In MBs',    _STATS_LABELS)
g_vm_encrypted_lbs       = Gauge('vm_EncryptedDataInLBs',         'VM Encrypted Data In LBs',             _STATS_LABELS)
g_vm_unencrypted_lbs     = Gauge('vm_UnencryptedDataInLBs',       'VM Unencrypted Data In LBs',           _STATS_LABELS)
g_vm_total_lbs           = Gauge('vm_TotalDataInLBs',             'VM Total Data In LBs',                 _STATS_LABELS)
g_vm_percent_encrypted   = Gauge('vm_PercentEncrypted',           'VM Percent Encrypted',                 _STATS_LABELS)
g_vm_trend_change_level  = Gauge('vm_TrendChangeLevel',           'VM Trend Change Level',                _STATS_LABELS)

# VPG metrics (GetDataFunc)
_VPG_LABELS = ['VpgIdentifier', 'VpgName', 'VpgPriority', 'SiteIdentifier', 'SiteName']
g_vpg_storage_used        = Gauge('vpg_storage_used_in_mb',                     'VPG Storage Used In MB',                     _VPG_LABELS)
g_vpg_actual_rpo          = Gauge('vpg_actual_rpo',                             'VPG Actual RPO',                             _VPG_LABELS)
g_vpg_throughput          = Gauge('vpg_throughput_in_mb',                       'VPG Throughput In MB',                       _VPG_LABELS)
g_vpg_iops                = Gauge('vpg_iops',                                   'VPG IOPs',                                   _VPG_LABELS)
g_vpg_provisioned_storage = Gauge('vpg_provisioned_storage_in_mb',              'VPG Provisioned Storage In MB',              _VPG_LABELS)
g_vpg_vms_count           = Gauge('vpg_vms_count',                              'VPG VMs Count',                              _VPG_LABELS)
g_vpg_configured_rpo      = Gauge('vpg_configured_rpo_seconds',                 'VPG Configured RPO Seconds',                 _VPG_LABELS)
g_vpg_actual_history      = Gauge('vpg_actual_history_in_minutes',              'VPG Actual History In Minutes',              _VPG_LABELS)
g_vpg_configured_history  = Gauge('vpg_configured_history_in_minutes',          'VPG Configured History In Minutes',          _VPG_LABELS)
g_vpg_failsafe_actual     = Gauge('vpg_failsafe_history_in_minutes_actual',     'VPG Failsafe History In Minutes Actual',     _VPG_LABELS)
g_vpg_failsafe_configured = Gauge('vpg_failsafe_history_in_minutes_configured', 'VPG Failsafe History In Minutes Configured', _VPG_LABELS)
g_vpg_status              = Gauge('vpg_status',                                 'VPG Status',                                 _VPG_LABELS)
g_vpg_substatus           = Gauge('vpg_substatus',                              'VPG Sub-Status',                             _VPG_LABELS)
g_vpg_alert_status        = Gauge('vpg_alert_status',                           'VPG Alert Status',                           _VPG_LABELS)

# Datastore metrics (GetDataFunc)
_DS_LABELS = ['datastoreIdentifier', 'DatastoreName', 'SiteIdentifier', 'SiteName']
g_ds_vras                         = Gauge('datastore_vras',                                      'Datastore VRAs',                                         _DS_LABELS)
g_ds_incoming_vms                 = Gauge('datastore_incoming_vms',                              'Datastore Incoming VMs',                                 _DS_LABELS)
g_ds_outgoing_vms                 = Gauge('datastore_outgoing_vms',                              'Datastore Outgoing VMs',                                 _DS_LABELS)
g_ds_capacity                     = Gauge('datastore_usage_capacityinbytes',                     'Datastore Capacity In Bytes',                            _DS_LABELS)
g_ds_free                         = Gauge('datastore_usage_freeinbytes',                         'Datastore Free In Bytes',                                _DS_LABELS)
g_ds_used                         = Gauge('datastore_usage_usedinbytes',                         'Datastore Used In Bytes',                                _DS_LABELS)
g_ds_provisioned                  = Gauge('datastore_usage_provisionedinbytes',                  'Datastore Provisioned In Bytes',                         _DS_LABELS)
g_ds_zerto_protected_used         = Gauge('datastore_usage_zerto_protected_usedinbytes',         'Datastore Zerto Protected Used In Bytes',                _DS_LABELS)
g_ds_zerto_protected_provisioned  = Gauge('datastore_usage_zerto_protected_provisionedinbytes',  'Datastore Zerto Protected Provisioned In Bytes',         _DS_LABELS)
g_ds_zerto_recovery_used          = Gauge('datastore_usage_zerto_recovery_usedinbytes',          'Datastore Zerto Recovery Used In Bytes',                 _DS_LABELS)
g_ds_zerto_recovery_provisioned   = Gauge('datastore_usage_zerto_recovery_provisionedinbytes',   'Datastore Zerto Recovery Provisioned In Bytes',          _DS_LABELS)
g_ds_zerto_journal_used           = Gauge('datastore_usage_zerto_journal_usedinbytes',           'Datastore Zerto Journal Used In Bytes',                  _DS_LABELS)
g_ds_zerto_journal_provisioned    = Gauge('datastore_usage_zerto_journal_provisionedinbytes',    'Datastore Zerto Journal Provisioned In Bytes',           _DS_LABELS)
g_ds_zerto_scratch_used           = Gauge('datastore_usage_zerto_scratch_usedinbytes',           'Datastore Zerto Scratch Used In Bytes',                  _DS_LABELS)
g_ds_zerto_scratch_provisioned    = Gauge('datastore_usage_zerto_scratch_provisionedinbytes',    'Datastore Zerto Scratch Provisioned In Bytes',           _DS_LABELS)
g_ds_zerto_appliances_used        = Gauge('datastore_usage_zerto_appliances_usedinbytes',        'Datastore Zerto Appliances Used In Bytes',               _DS_LABELS)
g_ds_zerto_appliances_provisioned = Gauge('datastore_usage_zerto_appliances_provisionedinbytes', 'Datastore Zerto Appliances Provisioned In Bytes',        _DS_LABELS)

# VM metrics (GetDataFunc - VMs section)
_VM_LABELS = ['VmIdentifier', 'VmName', 'VmSourceVRA', 'VmRecoveryVRA', 'VmPriority', 'SiteIdentifier', 'VpgName', 'SiteName']
g_vm_actualrpo             = Gauge('vm_actualrpo',                  'VM Actual RPO',                 _VM_LABELS)
g_vm_throughput            = Gauge('vm_throughput_in_mb',           'VM Throughput In MB',           _VM_LABELS)
g_vm_iops                  = Gauge('vm_iops',                       'VM IOPs',                       _VM_LABELS)
g_vm_journal_hard_limit    = Gauge('vm_journal_hard_limit',         'VM Journal Hard Limit',         _VM_LABELS)
g_vm_journal_warning_limit = Gauge('vm_journal_warning_limit',      'VM Journal Warning Limit',      _VM_LABELS)
g_vm_journal_used_storage  = Gauge('vm_journal_used_storage_mb',    'VM Journal Used Storage MB',    _VM_LABELS)
g_vm_outgoing_bandwidth    = Gauge('vm_outgoing_bandwidth_in_mbps', 'VM Outgoing Bandwidth In Mbps', _VM_LABELS)
g_vm_used_storage          = Gauge('vm_used_storage_in_MB',         'VM Used Storage In MB',         _VM_LABELS)
g_vm_provisioned_storage   = Gauge('vm_provisioned_storage_in_MB',  'VM Provisioned Storage In MB',  _VM_LABELS)
g_vm_status                = Gauge('vm_status',                     'VM Status',                     _VM_LABELS)
g_vm_substatus             = Gauge('vm_substatus',                  'VM Sub-Status',                 _VM_LABELS)

# Scratch and journal volume metrics (GetDataFunc - Volumes sections)
_VOL_LABELS = ['ProtectedVm', 'ProtectedVmIdentifier', 'OwningVRA', 'VpgName', 'SiteIdentifier', 'SiteName']
g_scratch_vol_size        = Gauge('scratch_volume_size_in_bytes',          'Scratch Volume Size In Bytes',           _VOL_LABELS)
g_journal_vol_size        = Gauge('vm_journal_volume_size_in_bytes',       'VM Journal Volume Size In Bytes',        _VOL_LABELS)
g_journal_vol_provisioned = Gauge('vm_journal_volume_provisioned_in_bytes','VM Journal Volume Provisioned In Bytes', _VOL_LABELS)
g_journal_vol_count       = Gauge('vm_journal_volume_count',               'VM Journal Volume Count',                _VOL_LABELS)

# VRA metrics (GetVraMetrics)
_VRA_LABELS = ['VraIdentifierStr', 'VraName', 'VraVersion', 'HostVersion', 'SiteIdentifier', 'SiteName']
g_vra_memory         = Gauge('vra_memory_in_GB',        'VRA Memory In GB',        _VRA_LABELS)
g_vra_vcpu_count     = Gauge('vra_vcpu_count',          'VRA vCPU Count',          _VRA_LABELS)
g_vra_protected_vms  = Gauge('vra_protected_vms',       'VRA Protected VMs',       _VRA_LABELS)
g_vra_protected_vpgs = Gauge('vra_protected_vpgs',      'VRA Protected VPGs',      _VRA_LABELS)
g_vra_protected_vols = Gauge('vra_protected_volumes',   'VRA Protected Volumes',   _VRA_LABELS)
g_vra_recovery_vms   = Gauge('vra_recovery_vms',        'VRA Recovery VMs',        _VRA_LABELS)
g_vra_recovery_vpgs  = Gauge('vra_recovery_vpgs',       'VRA Recovery VPGs',       _VRA_LABELS)
g_vra_recovery_vols  = Gauge('vra_recovery_volumes',    'VRA Recovery Volumes',    _VRA_LABELS)
g_vra_self_protected = Gauge('vra_self_protected_vpgs', 'VRA Self-Protected VPGs', _VRA_LABELS)
g_vra_cpu_usage      = Gauge('vra_cpu_usage_mhz',       'VRA CPU Usage MHz',       _VRA_LABELS)
g_vra_memory_usage   = Gauge('vra_memory_usage_mb',     'VRA Memory Usage MB',     _VRA_LABELS)

# Exporter / thread health metrics (ThreadProbe)
g_exporter_uptime = Gauge('exporter_uptime',        'Exporter Uptime In Minutes', ['ExporterInstance'])
g_thread_status   = Gauge('exporter_thread_status', 'Exporter Thread Status',     ['thread', 'ExporterInstance'])


# ---------------------------------------------------------------------------
# Thread which gets VM level encryption statistics from ZVM API
# ---------------------------------------------------------------------------
def _counter_delta(new, old, vm_id, metric):
    """Return new-old normally; if new < old, the ZVM counter reset (reboot).
    In that case return new as-is and log a warning so the spike is suppressed."""
    if new >= old:
        return new - old
    log.warning(f"Counter reset detected for VM {vm_id} metric '{metric}' "
                f"(old={old}, new={new}) - ZVM may have rebooted. Publishing raw value.")
    return new


def GetStatsFunc(zvm_instance):
    tempdb = TinyDB(storage=MemoryStorage)
    dbvm = Query()
    dbvpg = Query()

    zvm = zvm_instance
    while True:
        global siteId
        global siteName

        if zvm.is_authenticated():
            log.debug("Stats Collector Loop Running")

            statsapi_json = zvm.vms_statistics()
            log.debug(statsapi_json)
            vms_encryption_metrics = zvm.encryptiondetection_metrics_vms()

            if statsapi_json is not None:
                for vm in statsapi_json:
                    vmsiteinfo = zvm.vm(vmidentifier=vm['VmIdentifier'], vpgidentifier=vm['VpgIdentifier'])
                    if vmsiteinfo['ProtectedSite']['identifier'] == zvm.site_id:
                        log.debug(f"VM is protected at this site - {vm['VmIdentifier']}")

                        if 'EncryptionMetrics' not in vm:
                            vm['EncryptionMetrics'] = {}
                        vm['VmName'] = None
                        vm['SiteId'] = zvm.site_id

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
                                vm['EncryptionMetrics']['EncryptedData']    = vmem['EncryptionMetrics']['EncryptedData']
                                vm['EncryptionMetrics']['NonEncryptedData'] = vmem['EncryptionMetrics']['NonEncryptedData']
                                vm['EncryptionMetrics']['TrendChangeLevel'] = vmem['EncryptionMetrics']['TrendChangeLevel']
                                vm['VmName'] = vmem['Link']['name']

                        log.info("Checking TempDB for VM " + vm['VmIdentifier'] + " in VPG " + vm['VpgIdentifier'])
                        oldvmdata = tempdb.search((dbvm.VmIdentifier == vm['VmIdentifier']) & (dbvpg.VpgIdentifier == vm['VpgIdentifier']))
                        if oldvmdata:
                            log.info(vm['VmIdentifier'] + " Record Found, Updating DB")
                            log.debug("Old Data")
                            log.debug(oldvmdata)
                            log.debug(tempdb.update(vm, (dbvm.VmIdentifier == vm['VmIdentifier']) & (dbvpg.VpgIdentifier == vm['VpgIdentifier'])))
                            log.debug("New Data")
                            log.debug(vm)
                            log.debug("!@!@!@!@!@  Stats  !@!@!@!@!@")
                            VMName                            = oldvmdata[0]['VmName']
                            vid                               = vm['VmIdentifier']
                            log.debug("Current VM " + str(VMName))
                            CurrentIops                       = _counter_delta(vm['IoOperationsCounter'],                    oldvmdata[0]['IoOperationsCounter'],                    vid, 'IoOperationsCounter')
                            log.debug("CurrentIops " + str(CurrentIops))
                            CurrentSyncCounterInMBs           = _counter_delta(vm['SyncCounterInMBs'],                       oldvmdata[0]['SyncCounterInMBs'],                       vid, 'SyncCounterInMBs')
                            log.debug("CurrentSyncCounterInMBs " + str(CurrentSyncCounterInMBs))
                            CurrentNetworkTrafficCounterInMBs = _counter_delta(vm['NetworkTrafficCounterInMBs'],              oldvmdata[0]['NetworkTrafficCounterInMBs'],              vid, 'NetworkTrafficCounterInMBs')
                            log.debug("CurrentNetworkTrafficCounterInMBs " + str(CurrentNetworkTrafficCounterInMBs))
                            CurrentWriteCounterInMBs          = _counter_delta(vm['WriteCounterInMBs'],                      oldvmdata[0]['WriteCounterInMBs'],                      vid, 'WriteCounterInMBs')
                            log.debug("CurrentWriteCounterInMBs " + str(CurrentWriteCounterInMBs))
                            CurrentEncryptedLBs               = _counter_delta(vm['EncryptionMetrics']['EncryptedData'],     oldvmdata[0]['EncryptionMetrics']['EncryptedData'],     vid, 'EncryptedData')
                            log.debug("CurrentEncryptedLBs " + str(CurrentEncryptedLBs))
                            CurrentUnencryptedLBs             = _counter_delta(vm['EncryptionMetrics']['NonEncryptedData'],  oldvmdata[0]['EncryptionMetrics']['NonEncryptedData'],  vid, 'NonEncryptedData')
                            log.debug("CurrentUnencryptedLBs " + str(CurrentUnencryptedLBs))
                            CurrentTrendChangeLevel           = _counter_delta(vm['EncryptionMetrics']['TrendChangeLevel'],  oldvmdata[0]['EncryptionMetrics']['TrendChangeLevel'],  vid, 'TrendChangeLevel')
                            log.debug("CurrentTrendChangeLevel " + str(CurrentTrendChangeLevel))
                            CurrentTotalLBs                   = CurrentEncryptedLBs + CurrentUnencryptedLBs
                            log.debug("CurrentTotalLBs " + str(CurrentTotalLBs))
                            if CurrentTotalLBs != 0:
                                CurrentPercentEncrypted       = (CurrentEncryptedLBs / CurrentTotalLBs) * 100
                            else:
                                CurrentPercentEncrypted       = 0
                            log.debug("CurrentPercentEncrypted " + str(CurrentPercentEncrypted))
                        else:
                            log.info(f"{vm['VmIdentifier']} - {vm['VmName']} -  No Record Found, Inserting into DB")
                            log.debug(tempdb.insert(vm))

                        # Push calculated metrics to Prometheus Gauges
                        lbl = dict(
                            VpgIdentifier=str(vm['VpgIdentifier']),
                            VmIdentifier=str(vm['VmIdentifier']),
                            VmName=str(vm['VmName']),
                            SiteIdentifier=str(siteId),
                            SiteName=str(siteName)
                        )
                        g_vm_iops_counter.labels(**lbl).set(CurrentIops)
                        g_vm_write_counter.labels(**lbl).set(CurrentWriteCounterInMBs)
                        g_vm_sync_counter.labels(**lbl).set(CurrentSyncCounterInMBs)
                        g_vm_network_counter.labels(**lbl).set(CurrentNetworkTrafficCounterInMBs)
                        g_vm_encrypted_lbs.labels(**lbl).set(CurrentEncryptedLBs)
                        g_vm_unencrypted_lbs.labels(**lbl).set(CurrentUnencryptedLBs)
                        g_vm_total_lbs.labels(**lbl).set(CurrentTotalLBs)
                        g_vm_percent_encrypted.labels(**lbl).set(CurrentPercentEncrypted)
                        g_vm_trend_change_level.labels(**lbl).set(CurrentTrendChangeLevel)
                    else:
                        log.debug(f"VM is only recovering to this site, skipping metrics - {vm['VmIdentifier']}")
            else:
                log.debug("No VMS in Stats API")

            log.debug("Starting Sleep for " + str(scrape_speed) + " seconds")
            sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            sleep(1)


# ---------------------------------------------------------------------------
# Function which retrieves stats from various ZVM APIs
# ---------------------------------------------------------------------------
def GetDataFunc(zvm_instance):
    zvm = zvm_instance
    while True:
        global siteId
        global siteName

        if zvm.is_authenticated():
            log.info("Data Collector Loop Running")

            ### VPGs API
            vpg_json = zvm.vpgs()
            if vpg_json is not None:
                log.debug("Got VPG JSON")
                for vpg in vpg_json:
                    lbl = dict(
                        VpgIdentifier=vpg['VpgIdentifier'],
                        VpgName=vpg['VpgName'],
                        VpgPriority=str(vpg['Priority']),
                        SiteIdentifier=siteId,
                        SiteName=siteName
                    )
                    g_vpg_storage_used.labels(**lbl).set(vpg["UsedStorageInMB"])
                    g_vpg_actual_rpo.labels(**lbl).set(vpg["ActualRPO"])
                    g_vpg_throughput.labels(**lbl).set(vpg["ThroughputInMB"])
                    g_vpg_iops.labels(**lbl).set(vpg["IOPs"])
                    g_vpg_provisioned_storage.labels(**lbl).set(vpg["ProvisionedStorageInMB"])
                    g_vpg_vms_count.labels(**lbl).set(vpg["VmsCount"])
                    g_vpg_configured_rpo.labels(**lbl).set(vpg["ConfiguredRpoSeconds"])
                    g_vpg_actual_history.labels(**lbl).set(vpg["HistoryStatusApi"]["ActualHistoryInMinutes"])
                    g_vpg_configured_history.labels(**lbl).set(vpg["HistoryStatusApi"]["ConfiguredHistoryInMinutes"])
                    if vpg["FailSafeHistory"] is None:
                        g_vpg_failsafe_actual.labels(**lbl).set(0)
                        g_vpg_failsafe_configured.labels(**lbl).set(0)
                    else:
                        g_vpg_failsafe_actual.labels(**lbl).set(vpg["FailSafeHistory"]["ActualFailSafeHistory"])
                        g_vpg_failsafe_configured.labels(**lbl).set(vpg["FailSafeHistory"]["ConfiguredFailSafeHistory"])
                    g_vpg_status.labels(**lbl).set(vpg["Status"])
                    g_vpg_substatus.labels(**lbl).set(vpg["SubStatus"])
                    g_vpg_alert_status.labels(**lbl).set(vpg["AlertStatus"])
            else:
                log.debug("No VPGs Found")

            ### Datastores API
            ds_json = zvm.datastores()
            if ds_json is not None:
                log.debug("Got Datastores API")
                for ds in ds_json:
                    log.debug(f"Processing {ds['DatastoreName']}")
                    lbl = dict(
                        datastoreIdentifier=ds['DatastoreIdentifier'],
                        DatastoreName=ds['DatastoreName'],
                        SiteIdentifier=siteId,
                        SiteName=siteName
                    )
                    g_ds_vras.labels(**lbl).set(ds["Stats"]["NumVRAs"])
                    g_ds_incoming_vms.labels(**lbl).set(ds["Stats"]["NumIncomingVMs"])
                    g_ds_outgoing_vms.labels(**lbl).set(ds["Stats"]["NumOutgoingVMs"])
                    g_ds_capacity.labels(**lbl).set(ds["Stats"]["Usage"]["Datastore"]["CapacityInBytes"])
                    g_ds_free.labels(**lbl).set(ds["Stats"]["Usage"]["Datastore"]["FreeInBytes"])
                    g_ds_used.labels(**lbl).set(ds["Stats"]["Usage"]["Datastore"]["UsedInBytes"])
                    g_ds_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Datastore"]["ProvisionedInBytes"])
                    g_ds_zerto_protected_used.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Protected"]["UsedInBytes"])
                    g_ds_zerto_protected_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Protected"]["ProvisionedInBytes"])
                    g_ds_zerto_recovery_used.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Recovery"]["UsedInBytes"])
                    g_ds_zerto_recovery_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Recovery"]["ProvisionedInBytes"])
                    g_ds_zerto_journal_used.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Journal"]["UsedInBytes"])
                    g_ds_zerto_journal_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Journal"]["ProvisionedInBytes"])
                    g_ds_zerto_scratch_used.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Scratch"]["UsedInBytes"])
                    g_ds_zerto_scratch_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Scratch"]["ProvisionedInBytes"])
                    g_ds_zerto_appliances_used.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Appliances"]["UsedInBytes"])
                    g_ds_zerto_appliances_provisioned.labels(**lbl).set(ds["Stats"]["Usage"]["Zerto"]["Appliances"]["ProvisionedInBytes"])
            else:
                log.debug("No Datastores Found")

            ## Build host → VRA name lookup for source/recovery VRA labels
            host_to_vra = {}
            vras_for_lookup = zvm.vras()
            if vras_for_lookup:
                host_to_vra = {v['HostDisplayName']: v['VraName'] for v in vras_for_lookup}

            ## VMs API
            log.debug("Getting VMs API")
            vms_json = zvm.vms()
            if vms_json is not None:
                log.debug("Got VMs API")
                for vm in vms_json:
                    log.debug("Processing VM: " + str(vm['VmName']))
                    log.debug("Checking VM " + vm['VmIdentifier'] + " on Protected Site " + vm['ProtectedSite']['identifier'] + " against " + siteId)

                    if siteId == vm['ProtectedSite']['identifier']:
                        log.debug("Found VM " + vm['VmIdentifier'] + " on Protected Site")

                        if not isinstance(vm["ActualRPO"], int):
                            vm["ActualRPO"] = -1

                        lbl = dict(
                            VmIdentifier=str(vm['VmIdentifier']),
                            VmName=str(vm['VmName']),
                            VmSourceVRA=host_to_vra.get(str(vm['OwningHostName']), ''),
                            VmRecoveryVRA=host_to_vra.get(str(vm['RecoveryHostName']), ''),
                            VmPriority=str(vm['Priority']),
                            SiteIdentifier=str(siteId),
                            VpgName=str(vm['VpgName']),
                            SiteName=str(siteName)
                        )
                        g_vm_actualrpo.labels(**lbl).set(vm["ActualRPO"])
                        g_vm_throughput.labels(**lbl).set(vm["ThroughputInMB"])
                        g_vm_iops.labels(**lbl).set(vm["IOPs"])
                        g_vm_journal_hard_limit.labels(**lbl).set(vm["JournalHardLimit"]["LimitValue"])
                        g_vm_journal_warning_limit.labels(**lbl).set(vm["JournalWarningThreshold"]["LimitValue"])
                        g_vm_journal_used_storage.labels(**lbl).set(vm["JournalUsedStorageMb"])
                        g_vm_outgoing_bandwidth.labels(**lbl).set(vm["OutgoingBandWidthInMbps"])
                        g_vm_used_storage.labels(**lbl).set(vm["UsedStorageInMB"])
                        g_vm_provisioned_storage.labels(**lbl).set(vm["ProvisionedStorageInMB"])
                        g_vm_status.labels(**lbl).set(vm["Status"])
                        g_vm_substatus.labels(**lbl).set(vm["SubStatus"])
                        log.debug("Processed VM: " + str(vm['VmName']))
                    else:
                        log.debug("VM " + vm['VmIdentifier'] + " is protected to this site")
            else:
                log.debug("No VMs Found")

            ## Volumes API - Scratch Volumes
            log.debug("Getting Scratch Volumes")
            scratch_vols = zvm.volumes(volumetype="scratch")
            if scratch_vols is not None:
                log.debug("Got Scratch Volumes API")
                # Accumulate per-VM totals before setting gauges (multiple volumes per VM)
                scratch_accumulator = {}
                for volume in scratch_vols:
                    key = (
                        volume['ProtectedVm']['Name'],
                        volume['ProtectedVm']['Identifier'],
                        volume['OwningVm']['Name'],
                        volume['Vpg']['Name']
                    )
                    scratch_accumulator[key] = scratch_accumulator.get(key, 0) + volume["Size"]["UsedInBytes"]
                for (pvm, pvmid, owning_vra, vpg_name), size in scratch_accumulator.items():
                    g_scratch_vol_size.labels(
                        ProtectedVm=pvm, ProtectedVmIdentifier=pvmid,
                        OwningVRA=owning_vra, VpgName=vpg_name,
                        SiteIdentifier=siteId, SiteName=siteName
                    ).set(size)
            else:
                log.debug("No Scratch Volumes Found")

            ## Volumes API - Journal Volumes
            log.debug("Getting Journal Volumes")
            journal_vols = zvm.volumes(volumetype="journal")
            if journal_vols is not None:
                log.debug("Journal Volumes Exist")
                # Accumulate per-VM totals before setting gauges (multiple volumes per VM)
                journal_size_acc  = {}
                journal_prov_acc  = {}
                journal_count_acc = {}
                for volume in journal_vols:
                    log.debug("Journal Volume: " + volume['ProtectedVm']['Name'] + " Calculating total size...")
                    key = (
                        volume['ProtectedVm']['Name'],
                        volume['ProtectedVm']['Identifier'],
                        volume['OwningVm']['Name'],
                        volume['Vpg']['Name']
                    )
                    journal_size_acc[key]  = journal_size_acc.get(key, 0)  + volume["Size"]["UsedInBytes"]
                    journal_prov_acc[key]  = journal_prov_acc.get(key, 0)  + volume["Size"]["ProvisionedInBytes"]
                    journal_count_acc[key] = journal_count_acc.get(key, 0) + 1
                for key in journal_size_acc:
                    pvm, pvmid, owning_vra, vpg_name = key
                    lbl = dict(
                        ProtectedVm=pvm, ProtectedVmIdentifier=pvmid,
                        OwningVRA=owning_vra, VpgName=vpg_name,
                        SiteIdentifier=siteId, SiteName=siteName
                    )
                    g_journal_vol_size.labels(**lbl).set(journal_size_acc[key])
                    g_journal_vol_provisioned.labels(**lbl).set(journal_prov_acc[key])
                    g_journal_vol_count.labels(**lbl).set(journal_count_acc[key])
            else:
                log.debug("No Journal Volumes Exist")

            log.debug("Starting Sleep for " + str(scrape_speed) + " seconds")
            sleep(scrape_speed)
        else:
            log.debug("Waiting 1 second for Auth Token")
            sleep(1)


# ---------------------------------------------------------------------------
# Get VRA CPU and memory usage from vCenter Server
# ---------------------------------------------------------------------------
def GetVraMetrics(zvm_instance):
    log.debug("GetVraMetrics thread started")
    try:
        zvm = zvm_instance
        while True:
            global siteId
            global siteName

            log.debug("Checking Token in VRA CPU MEM Collector")
            if zvm.is_authenticated():
                log.info("VRA CPU MEM Collector Running")

                vras_json = zvm.vras()
                log.debug(vras_json)

                if vras_json is not None:
                    log.debug("VRA names: %s", vras_json)
                    # Clear stale label sets so upgraded VRAs don't appear twice
                    for g in (g_vra_memory, g_vra_vcpu_count, g_vra_protected_vms,
                              g_vra_protected_vpgs, g_vra_protected_vols,
                              g_vra_recovery_vms, g_vra_recovery_vpgs, g_vra_recovery_vols,
                              g_vra_self_protected, g_vra_cpu_usage, g_vra_memory_usage):
                        g.clear()
                    for vra in vras_json:
                        lbl = dict(
                            VraIdentifierStr=vra['VraIdentifierStr'],
                            VraName=vra['VraName'],
                            VraVersion=vra['VraVersion'],
                            HostVersion=vra['HostVersion'],
                            SiteIdentifier=siteId,
                            SiteName=siteName
                        )
                        g_vra_memory.labels(**lbl).set(vra["MemoryInGB"])
                        g_vra_vcpu_count.labels(**lbl).set(vra["NumOfCpus"])
                        g_vra_protected_vms.labels(**lbl).set(vra["ProtectedCounters"]["Vms"])
                        g_vra_protected_vpgs.labels(**lbl).set(vra["ProtectedCounters"]["Vpgs"])
                        g_vra_protected_vols.labels(**lbl).set(vra["ProtectedCounters"]["Volumes"])
                        g_vra_recovery_vms.labels(**lbl).set(vra["RecoveryCounters"]["Vms"])
                        g_vra_recovery_vpgs.labels(**lbl).set(vra["RecoveryCounters"]["Vpgs"])
                        g_vra_recovery_vols.labels(**lbl).set(vra["RecoveryCounters"]["Volumes"])
                        g_vra_self_protected.labels(**lbl).set(vra["SelfProtectedVpgs"])

                        log.debug("VRA Name: %s", vra['VraName'])
                        log.info(f"vCenter info: T/F = {is_vcenter_set} Host: {vcenter_host} u: {vcenter_user}")

                        if is_vcenter_set:
                            log.debug("vCenter Info Is Valid... Trying to get CPU and Memory usage for VRAs")
                            try:
                                log.debug("Trying to get stats from vCenter module")
                                vradata = vc_connection.get_cpu_mem_used(vra['VraName'])
                                if vradata is not None:
                                    for item in vradata:
                                        log.debug(item)
                                    cpu_usage_mhz   = vradata[0]
                                    memory_usage_mb = vradata[1]
                                    log.debug(f"VRA {vra['VraName']}) has CPU usage of {cpu_usage_mhz} MHz and memory usage of {memory_usage_mb} MB")
                                    g_vra_cpu_usage.labels(**lbl).set(cpu_usage_mhz)
                                    g_vra_memory_usage.labels(**lbl).set(memory_usage_mb)
                                else:
                                    log.info(f"No data returned for VRA {vra['VraName']} from vCenter")
                            except Exception as e:
                                log.info(f"No VM found with name {vra['VraName']}, or unexpected response: {e}")
                else:
                    log.debug("No VRAs Found")

                log.debug("Starting Sleep for " + str(int(scrape_speed * 2)) + " seconds")
                sleep(scrape_speed * 2)
            else:
                log.debug("Waiting 1 second for Auth Token")
                sleep(1)
    except Exception as e:
        log.error(f"Error in GetVraMetrics: {e}")


# ---------------------------------------------------------------------------
# Monitors thread health and exporter uptime
# ---------------------------------------------------------------------------
def ThreadProbe():
    global container_id
    while True:
        log.debug("Thread Probe Started")

        uptime = round((time() - start_time) / 60, 1)
        g_exporter_uptime.labels(ExporterInstance=container_id).set(uptime)

        g_thread_status.labels(thread="DataStats",      ExporterInstance=container_id).set(1 if data_thread.is_alive()        else 0)
        g_thread_status.labels(thread="EncryptionStats",ExporterInstance=container_id).set(1 if stats_thread.is_alive()       else 0)
        g_thread_status.labels(thread="VraMetrics",     ExporterInstance=container_id).set(1 if vra_metrics_thread.is_alive() else 0)

        log.debug("Probe Thread Going to Sleep")
        sleep(30)


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

class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for container stdout / fluentd ingestion."""
    def format(self, record):
        log_entry = {
            "time":      self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level":     record.levelname,
            "thread":    record.threadName,
            "message":   record.getMessage(),
            "container": container_id,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(JsonFormatter())
log = logging.getLogger("Node-Exporter")
log.setLevel(LOGLEVEL)
log.addHandler(log_handler)
log.info(f"Zerto-Node-Exporter - Version {version}")
log.info(f"Log Level: {LOGLEVEL}")
log.debug("Running with Variables:\nVerify SSL: " + str(verifySSL) + "\nZVM Host: " + zvm_url + "\nZVM Port: " + zvm_port + "\nClient-Id: " + client_id + "\nClient Secret: " + client_secret)

# Initialize zvmsite instance
zvm_instance = zvmsite(
    host=zvm_url,
    port=int(zvm_port),
    username=zvm_username,
    password=zvm_password,
    client_id=client_id,
    client_secret=client_secret,
    loglevel=LOGLEVEL,
    logger=log,
    stats=(DISABLE_STATS != "TRUE")
)

# Start the zvmsite authentication thread
zvm_instance.connect()

siteId = None
siteName = None

while siteId is None:
    if zvm_instance.is_authenticated():
        sleep(2)
        log.debug("Trying Set Global Vars")
        siteId = zvm_instance.site_id
        siteName = zvm_instance.site_name
    else:
        sleep(1)

# Check if vCenter is set; if not, disable VRA CPU/memory metrics
is_vcenter_set = True
if vcenter_host == "vcenter.local":
    log.error("vCenter Host not set. Please set the environment variable VCENTER_HOST, turning off VRA CPU and Memory metrics")
    is_vcenter_set = False
log.debug("vCenter data collection is enabled")
vc_connection = vcsite(vcenter_host, vcenter_user, vcenter_pwd, loglevel="debug", logger=log)

# Start prometheus metrics HTTP server (replaces the file-based SimpleHTTPRequestHandler)
# All Gauges from all threads are served thread-safely at http://host:<LISTEN_PORT>/metrics
start_http_server(listen_port)
log.info(f"Prometheus metrics server started on port {listen_port}")

# Starting collection threads
vra_metrics_thread = start_thread(lambda: GetVraMetrics(zvm_instance))
data_thread        = start_thread(lambda: GetDataFunc(zvm_instance))
stats_thread       = start_thread(lambda: GetStatsFunc(zvm_instance))
probe_thread       = start_thread(ThreadProbe)
log.debug("All collection threads started")

# Loop indefinitely - monitor and restart any crashed threads
while True:
    sleep(10)
    if not probe_thread.is_alive():
        log.error("Probe Thread Died - Restarting")
        probe_thread = start_thread(ThreadProbe)
    else:
        log.debug("Probe Thread is alive")
    if not data_thread.is_alive():
        log.error("Data Thread Died - Restarting")
        data_thread = start_thread(lambda: GetDataFunc(zvm_instance))
    else:
        log.debug("Data API Thread is alive")
    if not stats_thread.is_alive():
        log.error("Stats Thread Died - Restarting")
        stats_thread = start_thread(lambda: GetStatsFunc(zvm_instance))
    else:
        log.debug("Stats API Thread is alive")
    if not vra_metrics_thread.is_alive():
        log.error("VRA Metrics Thread Died - Restarting")
        vra_metrics_thread = start_thread(lambda: GetVraMetrics(zvm_instance))
    else:
        log.debug("VRA Metrics Thread is alive")
    sleep(api_timeout)
