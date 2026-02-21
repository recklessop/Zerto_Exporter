# Zerto Prometheus Exporter

A Python-based Prometheus exporter that scrapes the Zerto ZVM Appliance (ZVMA) REST API and exposes metrics for Prometheus scraping and Grafana visualization.

## Compatibility

| Component | Supported Versions |
|---|---|
| Zerto | ZVM Appliance (ZVMA) 10.x |
| vCenter / vSphere | 7.x, 8.x, 9.x (VCF 9) |
| pyvmomi | 9.0.0.0 |
| Prometheus | Any current release |
| Grafana | Any current release |

> **Note:** This exporter targets the ZVMA API (Keycloak-based authentication). It is **not** compatible with the legacy Windows-based ZVM.

> **pyvmomi and vSphere 9:** pyvmomi 9.0.0.0 supports vSphere 9.0 and maintains backward compatibility with the previous four vSphere releases (8.0, 8.0U1, 8.0U2, 8.0U3). Note that Broadcom has announced pyvmomi 9.0.0.0 is the last standalone release — future versions will be distributed as part of the unified [VCF Python SDK](https://developer.broadcom.com/vcf-python-sdk). This exporter will be updated accordingly when that becomes necessary.

## Quick Start

### Docker Hub (recommended)

```bash
docker run -d \
  -p 9999:9999 \
  -e ZVM_HOST=<zvm-ip-or-hostname> \
  -e ZVM_USERNAME=admin \
  -e ZVM_PASSWORD=<password> \
  -e VCENTER_HOST=<vcenter-ip-or-hostname> \
  -e VCENTER_USER=administrator@vsphere.local \
  -e VCENTER_PASSWORD=<password> \
  recklessop/zerto-exporter:stable
```

### Docker Compose

Clone the repo and edit `docker-compose.yml` with your environment values, then:

```bash
git clone https://github.com/recklessop/Zerto_Exporter.git
cd Zerto_Exporter
docker-compose up -d
```

### Build from source

```bash
git clone https://github.com/recklessop/Zerto_Exporter.git
cd Zerto_Exporter
docker build -t zerto-exporter .
docker run -d -p 9999:9999 -e ZVM_HOST=... zerto-exporter
```

## Docker Image Tags

| Tag | Description |
|---|---|
| `stable` | Latest stable release — recommended for production |
| `latest` | Same as stable, updated on every master merge |
| `3.1.0`, `3.0.0`, etc. | Pinned semantic versions |

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `ZVM_HOST` | Yes | — | IP or hostname of the ZVMA |
| `ZVM_PORT` | No | `443` | ZVMA API port |
| `ZVM_USERNAME` | No | `admin` | ZVMA local username |
| `ZVM_PASSWORD` | Yes | — | ZVMA password |
| `CLIENT_ID` | No | `zerto-client` | OAuth client ID (for client credentials auth) |
| `CLIENT_SECRET` | No | — | OAuth client secret (alternative to username/password) |
| `VCENTER_HOST` | No | — | vCenter IP or hostname — required for VRA CPU/memory metrics |
| `VCENTER_USER` | No | `administrator@vsphere.local` | vCenter username |
| `VCENTER_PASSWORD` | No | — | vCenter password |
| `VERIFY_SSL` | No | `False` | Set to `True` to enforce SSL certificate verification |
| `LISTEN_PORT` | No | `9999` | Port the metrics HTTP server listens on |
| `SCRAPE_SPEED` | No | `30` | Seconds between API scrape cycles |
| `API_TIMEOUT` | No | `5` | HTTP request timeout in seconds |
| `LOGLEVEL` | No | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `DISABLE_STATS` | No | `FALSE` | Set to `TRUE` to disable the encryption/IO stats thread |

## Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: zerto-exporter
    metrics_path: /metrics
    static_configs:
      - targets: ['<exporter-host>:9999']
```

## Metrics Reference

Metrics are served at `http://<host>:9999/metrics`.

### VM Protection Metrics

Scraped every `SCRAPE_SPEED` seconds from the ZVM `/v1/vms` API.

Labels: `VmIdentifier`, `VmName`, `VmSourceVRA`, `VmRecoveryVRA`, `VmPriority`, `SiteIdentifier`, `VpgName`, `SiteName`

| Metric | Description |
|---|---|
| `vm_actualrpo` | Current RPO in seconds |
| `vm_throughput_in_mb` | Replication throughput in MB/s |
| `vm_iops` | Replication IOPs |
| `vm_outgoing_bandwidth_in_mbps` | Outgoing WAN bandwidth in Mbps |
| `vm_used_storage_in_MB` | Used storage in MB |
| `vm_provisioned_storage_in_MB` | Provisioned storage in MB |
| `vm_journal_used_storage_mb` | Journal used storage in MB |
| `vm_journal_hard_limit` | Journal hard limit value |
| `vm_journal_warning_limit` | Journal warning threshold value |
| `vm_status` | VM protection status (numeric) |
| `vm_substatus` | VM protection sub-status (numeric) |

**VRA label behaviour:**
- `VmSourceVRA` — the VRA on the protected (source) side, e.g. `Z-VRA-192.168.50.21`
- `VmRecoveryVRA` — the VRA on the recovery side for local-to-local VPGs, e.g. `Z-VRA-192.168.50.22`; empty string for cloud targets (Azure, AWS) since there is no local VRA on the recovery side

### VM IO / Encryption Stats Metrics

Scraped every `SCRAPE_SPEED` seconds from the ZVM `/v1/vms/statistics` and encryption APIs. Reported as deltas (rate of change between scrape cycles).

Labels: `VpgIdentifier`, `VmIdentifier`, `VmName`, `SiteIdentifier`, `SiteName`

| Metric | Description |
|---|---|
| `vm_IoOperationsCounter` | IO operations delta |
| `vm_WriteCounterInMBs` | Write counter delta in MB |
| `vm_SyncCounterInMBs` | Sync counter delta in MB |
| `vm_NetworkTrafficCounterInMBs` | Network traffic delta in MB |
| `vm_EncryptedDataInLBs` | Encrypted data delta in logical blocks |
| `vm_UnencryptedDataInLBs` | Unencrypted data delta in logical blocks |
| `vm_TotalDataInLBs` | Total data delta in logical blocks |
| `vm_PercentEncrypted` | Percentage of data that is encrypted |
| `vm_TrendChangeLevel` | Encryption trend change level |

### VPG Metrics

Labels: `VpgIdentifier`, `VpgName`, `VpgPriority`, `SiteIdentifier`, `SiteName`

| Metric | Description |
|---|---|
| `vpg_actual_rpo` | VPG actual RPO in seconds |
| `vpg_throughput_in_mb` | VPG replication throughput in MB/s |
| `vpg_iops` | VPG replication IOPs |
| `vpg_storage_used_in_mb` | VPG used storage in MB |
| `vpg_provisioned_storage_in_mb` | VPG provisioned storage in MB |
| `vpg_vms_count` | Number of VMs in the VPG |
| `vpg_configured_rpo` | Configured RPO target in seconds |
| `vpg_actual_history` | Actual journal history in minutes |
| `vpg_configured_history` | Configured journal history in minutes |
| `vpg_failsafe_actual` | Actual failsafe history in minutes |
| `vpg_failsafe_configured` | Configured failsafe history in minutes |
| `vpg_status` | VPG status (numeric) |
| `vpg_substatus` | VPG sub-status (numeric) |
| `vpg_alert_status` | VPG alert status (numeric) |

### VRA Metrics

Scraped every `SCRAPE_SPEED * 2` seconds. CPU and memory usage require `VCENTER_HOST` to be configured.

Labels: `VraIdentifierStr`, `VraName`, `VraVersion`, `HostVersion`, `SiteIdentifier`, `SiteName`

| Metric | Description |
|---|---|
| `vra_memory_in_GB` | Configured VRA memory in GB |
| `vra_vcpu_count` | Configured VRA vCPU count |
| `vra_protected_vms` | Number of VMs protected by this VRA |
| `vra_protected_vpgs` | Number of VPGs protected by this VRA |
| `vra_protected_volumes` | Number of volumes protected by this VRA |
| `vra_recovery_vms` | Number of VMs recovering to this VRA |
| `vra_recovery_vpgs` | Number of VPGs recovering to this VRA |
| `vra_recovery_volumes` | Number of volumes recovering to this VRA |
| `vra_self_protected_vpgs` | Number of self-protected VPGs |
| `vra_cpu_usage_mhz` | VRA VM CPU usage in MHz (requires vCenter) |
| `vra_memory_usage_mb` | VRA VM memory usage in MB (requires vCenter) |

### Volume Metrics

Labels: `ProtectedVm`, `ProtectedVmIdentifier`, `OwningVRA`, `VpgName`, `SiteIdentifier`, `SiteName`

| Metric | Description |
|---|---|
| `scratch_volume_size_in_bytes` | Total scratch volume size in bytes |
| `vm_journal_volume_size_in_bytes` | Journal volume used size in bytes |
| `vm_journal_volume_provisioned_in_bytes` | Journal volume provisioned size in bytes |
| `vm_journal_volume_count` | Number of journal volumes |

### Datastore Metrics

Labels: `datastoreIdentifier`, `DatastoreName`, `SiteIdentifier`, `SiteName`

| Metric | Description |
|---|---|
| `datastore_vras` | Number of VRAs on this datastore |
| `datastore_incoming_vms` | Number of incoming (recovery) VMs |
| `datastore_outgoing_vms` | Number of outgoing (protected) VMs |
| `datastore_capacity_in_bytes` | Total datastore capacity |
| `datastore_free_in_bytes` | Free space |
| `datastore_used_in_bytes` | Used space |
| `datastore_provisioned_in_bytes` | Provisioned space |
| `datastore_usage_zerto_protected_*` | Zerto protected volume usage |
| `datastore_usage_zerto_recovery_*` | Zerto recovery volume usage |
| `datastore_usage_zerto_journal_*` | Zerto journal volume usage |
| `datastore_usage_zerto_scratch_*` | Zerto scratch volume usage |
| `datastore_usage_zerto_appliances_*` | Zerto appliance volume usage |

### Exporter Health Metrics

Labels: `ExporterInstance`

| Metric | Description |
|---|---|
| `exporter_uptime` | Exporter uptime in minutes |
| `exporter_thread_status` | Per-thread health (1=alive, 0=dead); thread label values: `DataStats`, `EncryptionStats`, `VraMetrics` |

## Changelog

### 3.1.0
- Added `VmSourceVRA` label to all VM protection metrics, populated from the VRA on the protected side
- `VmRecoveryVRA` now resolves to the VRA name (e.g. `Z-VRA-192.168.50.21`) instead of the raw ESXi host IP
- Cloud-target VPGs (Azure, AWS) correctly emit `VmRecoveryVRA=""` since there is no local VRA on the recovery side
- Upgraded pyvmomi to 9.0.0.0
- Azure pipeline now publishes `{semver}`, `stable`, and `latest` tags

### 3.0.0
- Fix duplicate VRA metrics after VRA upgrade
- Fix counter spike/negative values on ZVM reboot
- Removed leaked credentials

## Acknowledgements

Huge shout out to [hmdhszd](https://github.com/hmdhszd/Custom_Prometheus_Node_Exporter-in-Python) for the framework that started this project.
