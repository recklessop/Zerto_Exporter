# Zerto Exporter: metrics handoff

This covers every metric the Zerto Prometheus exporter
([recklessop/Zerto_Exporter](https://github.com/recklessop/Zerto_Exporter)) publishes, where each
one comes from, and what it means. It was written against `master` at commit `6064626` (Feb 2026,
version 3.1.x).

All metric definitions are in `app/python-node-exporter.py`. The ZVM API client is
`app/zvma10/zvma.py`, and the vCenter client is `app/vmware/vcenter.py`.

## How it works

The exporter is one Python process. It logs in to the Zerto ZVM Appliance (ZVMA 10.x, Keycloak
auth) and runs four background threads. Each thread polls an API and writes the results to
Prometheus **gauges**, which are served at `http://<host>:9999/metrics`.

| Thread | Function | Polls | Every | Metric families |
|---|---|---|---|---|
| Data | `GetDataFunc` | ZVM `/v1/vpgs`, `/v1/datastores`, `/v1/vras`, `/v1/vms`, `/v1/volumes` | `SCRAPE_SPEED` (30s) | `vpg_*`, `datastore_*`, `vm_*` (protection), volume metrics |
| Stats | `GetStatsFunc` | ZVM `/v1/statistics/vms`, `/v1/encryptionDetection/metrics/vms`, `/v1/vms/{id}` | `SCRAPE_SPEED` (30s) | `vm_*Counter*`, `vm_*LBs`, encryption metrics |
| VRA | `GetVraMetrics` | ZVM `/v1/vras`, plus vCenter (pyVmomi) | `SCRAPE_SPEED × 2` (60s) | `vra_*` |
| Probe | `ThreadProbe` | Nothing (local) | 30s | `exporter_*` |

The main loop restarts any thread that dies. The Prometheus scrape interval is separate: Prometheus
reads whatever value is in the gauges at scrape time, so scraping faster than 30s gets you nothing
new.

**Site scoping:** VM-level metrics only cover VMs **protected at this site**, meaning the VM's
`ProtectedSite` matches the ZVM's own site ID. VMs that only recover to this site are skipped. To
see both directions, run one exporter per ZVM. VPG, datastore, and VRA metrics are not filtered.

Every metric carries `SiteIdentifier` and `SiteName` labels, which come from the ZVM you're
connected to.

---

## 1. VM protection metrics (Data thread, `/v1/vms`)

Labels: `VmIdentifier`, `VmName`, `VmSourceVRA`, `VmRecoveryVRA`, `VmPriority`, `VpgName`,
`SiteIdentifier`, `SiteName`

| Metric | API field | Meaning |
|---|---|---|
| `vm_actualrpo` | `ActualRPO` | Current RPO in seconds: how far behind the replica is. Set to **-1** when the API returns a non-integer (e.g. null during initial sync). |
| `vm_throughput_in_mb` | `ThroughputInMB` | Replication throughput, MB/s. |
| `vm_iops` | `IOPs` | Write IOPS that Zerto is replicating for this VM. |
| `vm_outgoing_bandwidth_in_mbps` | `OutgoingBandWidthInMbps` | WAN bandwidth used by this VM's replication, Mbps (bits, not bytes). |
| `vm_used_storage_in_MB` | `UsedStorageInMB` | Storage used by the VM's disks, MB. |
| `vm_provisioned_storage_in_MB` | `ProvisionedStorageInMB` | Provisioned size of the VM's disks, MB. |
| `vm_journal_used_storage_mb` | `JournalUsedStorageMb` | Space the recovery journal currently takes up, MB. |
| `vm_journal_hard_limit` | `JournalHardLimit.LimitValue` | Journal hard limit. Once the journal reaches it, Zerto starts dropping the oldest history. |
| `vm_journal_warning_limit` | `JournalWarningThreshold.LimitValue` | Journal size at which Zerto raises a warning. |
| `vm_status` | `Status` | Protection status as a number (see [status codes](#status-codes)). |
| `vm_substatus` | `SubStatus` | Detailed sub-status as a number. |

How the VRA labels are filled in: the exporter builds a host name → VRA name map from `/v1/vras`.
`VmSourceVRA` is the VRA on the VM's `OwningHostName`, and `VmRecoveryVRA` is the VRA on
`RecoveryHostName`. `VmRecoveryVRA` is `""` for cloud targets (Azure/AWS), and also whenever the
recovery host isn't managed by this ZVM.

> ⚠️ The journal limit fields drop the limit **type**. The Zerto API pairs `LimitValue` with a
> type (unlimited / MB / percentage), so the same number can mean different things on different
> VPGs. Check the VPG settings before alerting on these.

## 2. VM IO and encryption stats (Stats thread)

Labels: `VpgIdentifier`, `VmIdentifier`, `VmName`, `SiteIdentifier`, `SiteName`

These come from `/v1/statistics/vms` (running IO counters) joined with
`/v1/encryptionDetection/metrics/vms` (Zerto's ransomware / encryption-detection counters). The
API returns **cumulative counters**. The exporter keeps the previous reading in an in-memory TinyDB
and publishes the **difference since the last cycle**.

| Metric | Source field | Meaning |
|---|---|---|
| `vm_IoOperationsCounter` | `IoOperationsCounter` | IO operations during the last cycle. |
| `vm_WriteCounterInMBs` | `WriteCounterInMBs` | MB written by the VM during the last cycle. |
| `vm_SyncCounterInMBs` | `SyncCounterInMBs` | MB moved by sync operations (initial sync / bitmap sync / delta sync) during the last cycle. |
| `vm_NetworkTrafficCounterInMBs` | `NetworkTrafficCounterInMBs` | MB sent over the network for this VM during the last cycle. |
| `vm_EncryptedDataInLBs` | `EncryptionMetrics.EncryptedData` | Logical blocks written that **looked encrypted**. |
| `vm_UnencryptedDataInLBs` | `EncryptionMetrics.NonEncryptedData` | Logical blocks written that looked normal. |
| `vm_TotalDataInLBs` | computed | `Encrypted + Unencrypted` for the cycle. |
| `vm_PercentEncrypted` | computed | `Encrypted / Total × 100` for the cycle (0 if nothing was written). A sudden jump here is the ransomware signal. |
| `vm_TrendChangeLevel` | `EncryptionMetrics.TrendChangeLevel` | Zerto's trend-change score for the VM. **Note:** the exporter deltas this like the counters, even though it looks like a level, not a cumulative counter. Treat it with suspicion. |

Things to know about these:

- **The values are per cycle, not per second.** With the default `SCRAPE_SPEED=30`,
  `vm_IoOperationsCounter` is IOs per 30 seconds, so divide by 30 for IOPS. These are gauges that
  already hold deltas, so **don't wrap them in `rate()`**.
- **The first cycle after startup publishes 0** for every VM, because there's no previous reading
  to subtract.
- **Counter resets** (ZVM reboot, new < old) publish the raw new value and log a warning, which
  avoids a negative spike.
- **The thread makes one extra API call per VM**: each cycle it calls `/v1/vms/{id}` for every VM
  to check the protected site. Large environments will feel this.
- Setting `DISABLE_STATS=TRUE` makes the ZVM client skip stats collection.

## 3. VPG metrics (Data thread, `/v1/vpgs`)

Labels: `VpgIdentifier`, `VpgName`, `VpgPriority`, `SiteIdentifier`, `SiteName`

| Metric | API field | Meaning |
|---|---|---|
| `vpg_actual_rpo` | `ActualRPO` | Current RPO of the VPG, seconds (the worst VM in the group). |
| `vpg_configured_rpo_seconds` | `ConfiguredRpoSeconds` | RPO alert threshold configured on the VPG. Alert when actual > configured. |
| `vpg_throughput_in_mb` | `ThroughputInMB` | Replication throughput for the whole VPG, MB/s. |
| `vpg_iops` | `IOPs` | Replicated write IOPS for the whole VPG. |
| `vpg_storage_used_in_mb` | `UsedStorageInMB` | Storage used by the VPG's VMs, MB. |
| `vpg_provisioned_storage_in_mb` | `ProvisionedStorageInMB` | Provisioned storage of the VPG's VMs, MB. |
| `vpg_vms_count` | `VmsCount` | Number of VMs in the VPG. |
| `vpg_actual_history_in_minutes` | `HistoryStatusApi.ActualHistoryInMinutes` | How far back you can currently recover (journal depth), minutes. |
| `vpg_configured_history_in_minutes` | `HistoryStatusApi.ConfiguredHistoryInMinutes` | Configured journal history target, minutes. Actual < configured means the journal is too small or was recently reset. |
| `vpg_failsafe_history_in_minutes_actual` | `FailSafeHistory.ActualFailSafeHistory` | Actual failsafe history, minutes. 0 if failsafe isn't configured. |
| `vpg_failsafe_history_in_minutes_configured` | `FailSafeHistory.ConfiguredFailSafeHistory` | Configured failsafe history, minutes. 0 if not configured. |
| `vpg_status` | `Status` | VPG status code (see below). |
| `vpg_substatus` | `SubStatus` | VPG sub-status code. |
| `vpg_alert_status` | `AlertStatus` | Alert state code. |

## 4. Datastore metrics (Data thread, `/v1/datastores`)

Labels: `datastoreIdentifier` (lowercase `d`), `DatastoreName`, `SiteIdentifier`, `SiteName`

| Metric | Meaning |
|---|---|
| `datastore_vras` | Number of VRAs with disks on this datastore. |
| `datastore_incoming_vms` | VMs replicating **into** this datastore (recovery side). |
| `datastore_outgoing_vms` | Protected VMs whose disks are **on** this datastore (source side). |
| `datastore_usage_capacityinbytes` | Total datastore capacity, bytes. |
| `datastore_usage_freeinbytes` | Free space, bytes. |
| `datastore_usage_usedinbytes` | Used space, bytes. |
| `datastore_usage_provisionedinbytes` | Provisioned space (thin disks at full size), bytes. |

Zerto's own share of the datastore, each reported as `_usedinbytes` and `_provisionedinbytes`:

| Metric prefix | What the space is |
|---|---|
| `datastore_usage_zerto_protected_*` | Disks of protected (source) VMs on this datastore. |
| `datastore_usage_zerto_recovery_*` | Replica (recovery) disks Zerto keeps here. |
| `datastore_usage_zerto_journal_*` | Journal disks. |
| `datastore_usage_zerto_scratch_*` | Scratch disks (used during failover tests and recovery to hold writes). |
| `datastore_usage_zerto_appliances_*` | VRA appliance disks. |

## 5. Volume metrics (Data thread, `/v1/volumes`)

Labels: `ProtectedVm`, `ProtectedVmIdentifier`, `OwningVRA`, `VpgName`, `SiteIdentifier`,
`SiteName`

A VM can have several volumes. The exporter adds them up per (VM, owning VRA, VPG) before
publishing.

| Metric | Meaning |
|---|---|
| `vm_journal_volume_size_in_bytes` | Total used size of the VM's journal volumes, bytes. |
| `vm_journal_volume_provisioned_in_bytes` | Total provisioned size of the VM's journal volumes, bytes. |
| `vm_journal_volume_count` | Number of journal volumes for the VM (grows as the journal expands). |
| `scratch_volume_size_in_bytes` | Total used size of the VM's scratch volumes, bytes. Non-zero mostly during test failovers. |

## 6. VRA metrics (VRA thread, `/v1/vras` + vCenter)

Labels: `VraIdentifierStr`, `VraName`, `VraVersion`, `HostVersion`, `SiteIdentifier`, `SiteName`

From the ZVM:

| Metric | Meaning |
|---|---|
| `vra_memory_in_GB` | Memory configured on the VRA VM, GB. |
| `vra_vcpu_count` | vCPUs configured on the VRA VM. |
| `vra_protected_vms` | VMs this VRA is protecting (source side). |
| `vra_protected_vpgs` | VPGs this VRA is protecting. |
| `vra_protected_volumes` | Volumes this VRA is protecting. |
| `vra_recovery_vms` | VMs replicating into this VRA (target side). |
| `vra_recovery_vpgs` | VPGs replicating into this VRA. |
| `vra_recovery_volumes` | Volumes replicating into this VRA. |
| `vra_self_protected_vpgs` | VPGs where this VRA is both source and target (local replication on the same host). |

From vCenter (needs `VCENTER_HOST`, `VCENTER_USER` and `VCENTER_PASSWORD`). The exporter looks up
a vCenter VM whose name equals `VraName` and reads its `summary.quickStats`:

| Metric | vSphere field | Meaning |
|---|---|---|
| `vra_cpu_usage_mhz` | `overallCpuUsage` | VRA CPU usage, MHz. |
| `vra_memory_usage_mb` | `guestMemoryUsage` | VRA **active** guest memory, MB (memory the guest touched recently, not memory allocated on the host). |

The VRA gauges are cleared at the start of every cycle so an upgraded VRA (new version label)
doesn't show up twice.

`vcenter.py` also has `get_write_iops()` and `get_average_write_latency()`, which query vSphere
perf counters, but **nothing calls them and no metric is published from them**. They use hardcoded
counter IDs (6 and 10), which differ between vCenters and are wrong for those purposes anyway. If
you wire them up, use the counter names in
[section 8](#8-vsphere-disk-counters-reference-not-exported-yet) instead.

## 7. Exporter health (Probe thread)

| Metric | Labels | Meaning |
|---|---|---|
| `exporter_uptime` | `ExporterInstance` (container hostname) | Minutes since the exporter started. |
| `exporter_thread_status` | `thread`, `ExporterInstance` | 1 = alive, 0 = dead. `thread` is `DataStats`, `EncryptionStats` or `VraMetrics`. |

## 8. vSphere disk counters (reference, not exported yet)

The exporter doesn't publish any of these today. They're the pyVmomi perf counters to use if you
want vSphere's own view of IOPS and throughput per disk or per VM. That view is different from
Zerto's `vm_iops`, which counts only replicated writes.

Counter names are `group.name.rollup`, built from each counter's `groupInfo.key`, `nameInfo.key`
and `rollupType`. **Don't hardcode counter IDs.** vCenter assigns them per installation, and an
ESXi host can number them differently from its vCenter. Look the IDs up by name on whatever
endpoint you connect to.

### Per virtual disk

Query the VM with `instance="*"`. You get one series per disk, with the instance set to the bus
address (`scsi0:0`, `nvme0:1`, …).

| Counter | Measures | Unit |
|---|---|---|
| `virtualDisk.numberReadAveraged.average` | Read IOPS | IO/s |
| `virtualDisk.numberWriteAveraged.average` | Write IOPS | IO/s |
| `virtualDisk.read.average` | Read throughput | KB/s |
| `virtualDisk.write.average` | Write throughput | KB/s |
| `virtualDisk.totalReadLatency.average` | Read latency | ms |
| `virtualDisk.totalWriteLatency.average` | Write latency | ms |

### Per VM total

Query the VM with `instance=""` to get the VM-wide total.

| Counter | Measures | Unit |
|---|---|---|
| `disk.numberReadAveraged.average` | Read IOPS | IO/s |
| `disk.numberWriteAveraged.average` | Write IOPS | IO/s |
| `disk.commandsAveraged.average` | Total IOPS | IO/s |
| `disk.read.average` / `disk.write.average` | Read / write throughput | KB/s |
| `disk.usage.average` | Total throughput | KB/s |

The `disk.*` counters track physical device IO, so they can come back empty for VMs on NFS or
vSAN. The `virtualDisk.*` counters work on any storage. For a reliable VM total, query
`virtualDisk.*` with `instance="*"` and add up the disks.

### Where the data lives

- **Real-time data comes from the ESXi host.** Real-time stats (`intervalId=20`, one sample every
  20s) are collected on the host. Querying ESXi directly gets you about the last hour. Querying
  vCenter gives the same data: vCenter fetches it from the host that runs the VM.
- **Historical rollups are vCenter-only.** The 5 min, 30 min, 2 h and 1 day rollups are stored in
  the vCenter database, so you need vCenter for anything older than an hour.
- **The values are already per-second rates.** `maxSample=3` gives the last minute, and you can
  average those samples directly.

### Example: per-disk stats with disk names

The counter instance is a bus address. `disk_labels()` maps it to the disk name vSphere shows
("Hard disk 2") by matching each disk's controller bus number and unit number.

```python
from pyVmomi import vim

def counter_ids(perf):
    return {f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}": c.key
            for c in perf.perfCounter}

def disk_labels(vm):
    """Map perf instance ('scsi0:1') -> disk label ('Hard disk 2')."""
    devs = vm.config.hardware.device
    ctrls = {d.key: d for d in devs if isinstance(d, vim.vm.device.VirtualController)}
    bus = {vim.vm.device.VirtualSCSIController: "scsi",
           vim.vm.device.VirtualNVMEController: "nvme",
           vim.vm.device.VirtualSATAController: "sata",
           vim.vm.device.VirtualIDEController: "ide"}
    out = {}
    for d in devs:
        if isinstance(d, vim.vm.device.VirtualDisk):
            c = ctrls[d.controllerKey]
            prefix = next(p for t, p in bus.items() if isinstance(c, t))
            out[f"{prefix}{c.busNumber}:{d.unitNumber}"] = d.deviceInfo.label
    return out

WANT = ["virtualDisk.numberReadAveraged.average", "virtualDisk.numberWriteAveraged.average",
        "virtualDisk.read.average", "virtualDisk.write.average"]

def disk_stats(si, vm):
    perf = si.RetrieveContent().perfManager
    ids = counter_ids(perf)
    names = {v: k for k, v in ids.items()}
    spec = vim.PerformanceManager.QuerySpec(
        entity=vm, intervalId=20, maxSample=3,          # 3 x 20s = last minute
        metricId=[vim.PerformanceManager.MetricId(counterId=ids[n], instance="*") for n in WANT])
    labels = disk_labels(vm)
    result = perf.QueryStats(querySpec=[spec])
    if not result:                                      # powered off / no data
        return {}
    stats = {}
    for s in result[0].value:
        disk = labels.get(s.id.instance, s.id.instance)
        stats.setdefault(disk, {})[names[s.id.counterId]] = sum(s.value) / len(s.value)
    return stats
```

This returns a dict like `{"Hard disk 1": {"virtualDisk.numberWriteAveraged.average": 42.0, ...}}`.
It works the same against vCenter or ESXi. The snippet hasn't been run against a live vCenter yet:
check the `nvme` and `sata` instance prefixes first on a VM that has those controllers.

---

## Status codes

`vm_status`, `vpg_status`, `vpg_substatus` and `vpg_alert_status` are numeric enums. The ZVM itself
serves the authoritative mapping (`/v1/vpgs/statuses` and `/v1/vpgs/substatuses`; `zvma.py` has
`vpg_statuses()` and `vpg_substatuses()`). The common values are below. Check them against your ZVM
version before building alerts on them.

| `Status` | Meaning |
|---|---|
| 0 | Initializing |
| 1 | MeetingSLA |
| 2 | NotMeetingSLA |
| 3 | RpoNotMeetingSLA |
| 4 | HistoryNotMeetingSLA |
| 5 | FailingOver |
| 6 | Moving |
| 7 | Deleting |
| 8 | Recovered |

| `AlertStatus` | Meaning |
|---|---|
| 0 | None |
| 1 | Warning |
| 2 | Error |

## Gotchas

1. **The README metric names don't all match the code.** Use the names in this doc (taken from the
   code). The README's mistakes:
   - `vpg_configured_rpo` → really `vpg_configured_rpo_seconds`
   - `vpg_actual_history` / `vpg_configured_history` → really `..._in_minutes`
   - `vpg_failsafe_actual` / `vpg_failsafe_configured` → really
     `vpg_failsafe_history_in_minutes_actual` / `..._configured`
   - `datastore_capacity_in_bytes`, `datastore_free_in_bytes`, etc. → really
     `datastore_usage_capacityinbytes`, `datastore_usage_freeinbytes`, etc.
2. **Stale series stick around.** Apart from the VRA gauges, nothing clears old label sets. A
   deleted VM or VPG keeps reporting its last value until the exporter restarts.
3. **The vCenter on/off check never turns vCenter off.** The code disables vCenter only if
   `VCENTER_HOST == "vcenter.local"`, but the default is `192.168.50.20`. If you don't set it, the
   exporter keeps trying to reach a lab IP and logs failures every 60s.
4. **There are lab credentials in the source.** `python-node-exporter.py` and `docker-compose.yml`
   ship default ZVM and vCenter passwords and an OAuth client secret. At `DEBUG` (the code's
   default log level) the client secret is printed to the log at startup. Always set real values
   through env vars, run at `INFO`, and keep the defaults out of anything you build on this.
5. **Two different "IOPS" numbers:**
   - `vm_iops` / `vpg_iops` are Zerto's own instantaneous replication IOPS.
   - `vm_IoOperationsCounter` is a per-30-second delta of a running counter.

   They won't match exactly. Use `vm_iops` for dashboards, and the counters when you want totals
   over time.
