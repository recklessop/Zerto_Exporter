from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
import ssl

# Create an SSL context without certificate verification
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

si = SmartConnect(host='192.168.50.50', 
    user='administrator@vsphere.local', 
    pwd='Zertodata987!', 
    sslContext=context
)

# Find the virtual machine by name
vm_name = 'Squid'
content = si.RetrieveContent()
vm = None

for obj in content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True).view:
    if obj.name == vm_name:
        vm = obj
        break

if vm is None:
    print(f"Virtual machine '{vm_name}' not found")
    si.Disconnect()
    exit(1)

# Get performance manager
perf_manager = content.perfManager

# Define the metric ID for write IOPS (counterId = 6)
metric_id = vim.PerformanceManager.MetricId(counterId=6, instance="")

# Create a real-time query specification
query_spec = vim.PerformanceManager.QuerySpec(
    entity=vm,
    metricId=[metric_id],
    format="normal",
)

# Query the performance statistics
result = perf_manager.QueryStats(querySpec=[query_spec])

if result:
    # Get the latest write IOPS value
    write_iops = result[0].value[0].value
    print(f"Current write IOPS for {vm_name}: {write_iops}")

# Disconnect from vCenter Server
Disconnect(si)






