# Class for holding variables related to a site.
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
import ssl
import datetime
import logging
import socket
from logging.handlers import RotatingFileHandler

class vcsite:
    def __init__(self, host, username, password, port=443, verify_ssl=False, loglevel="INFO", logger=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.version = None
        self.__conn__ = None
        self.LOGLEVEL = loglevel.upper()
        self.log = None

        if logger is None:
            #set log line format including container_id
            container_id = str(socket.gethostname())
            log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")
            log_handler = RotatingFileHandler(filename=f"./logs/Log-{container_id}.log", maxBytes=1024*1024*100, backupCount=5)
            log_handler.setFormatter(log_formatter)
            self.log = logging.getLogger("vCenter Module")
            self.log.setLevel(self.LOGLEVEL)
            self.log.addHandler(log_handler)
        else:
            self.log = logger

    def connect(self):
        self.log.info(f"Log Level set to {self.LOGLEVEL}")
        if self.__conn__ is None:
            context = ssl.create_default_context()
            if not self.verify_ssl:
                log.debug("dont verify SSL")
                # Create an SSL context without certificate verification
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            # connect to vCenter Server
            si = None
            try:
                self.__conn__ = SmartConnect(host=self.host, user=self.username, pwd=self.password, sslContext=context)
                about_info = self.__conn__.content.about
                version = about_info.version
                self.version = version
                self.log.debug("Connected to vCenter Server %s", self.host)
            except Exception as e:
                self.log.error(f"Error connecting to vCenter Server: {e}")

    def version(self):
        return self.version

    def get_cpu_mem_used(self, vra):
            if vra == None:
                self.log.debug("Get_cpu_mem_used called with no vm name...returning no data")
                return
            if self.__conn__ == None:
                self.log.debug("Trying to get VRA stats without vCenter connection, trying to connect")
                self.connect()

            # get the root folder of the vCenter Server
            try:
                content = self.__conn__.RetrieveContent()
                root_folder = content.rootFolder
            except:
                self.log.debug("Could not get content from vCenter when trying to get VRA stats")

            # create a view for all VMs on the vCenter Server
            view_manager = content.viewManager
            vm_view = view_manager.CreateContainerView(root_folder, [vim.VirtualMachine], True)

            vm = None
            for vm_obj in vm_view.view:
                if str(vm_obj.name) == str(vra):
                    vm = vm_obj
                if vm is not None:
                    self.log.debug(f"Found VRA VM in vCenter with name {vm.name}")
                    # get the CPU usage and memory usage for the VM
                    cpu_usage_mhz = vm.summary.quickStats.overallCpuUsage
                    memory_usage_mb = vm.summary.quickStats.guestMemoryUsage

                    # print the CPU and memory usage for the VM
                    self.log.info(f"VM {vm.name} has CPU usage of {cpu_usage_mhz} MHz and memory usage of {memory_usage_mb} MB")
                    return [cpu_usage_mhz, memory_usage_mb]
                else:
                    self.log.debug(f"{vm_obj.name} is not a VRA")
            raise ValueError("No VRA Found")
            
    def get_write_iops(self, vm):
        try:
            content = self.__conn__.RetrieveContent()
        except:
            self.log.debug("Could not get content from vCenter when trying to get VRA stats")

        # Find the virtual machine by name
        vm_name = str(vm)
        vm = None

        for obj in content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True).view:
            if obj.name == vm_name:
                vm = obj
                break

        if vm is None:
            print(f"Virtual machine '{vm_name}' not found")
            return

        # Get performance manager
        perf_manager = content.perfManager

        # Define the metric ID for write IOPS (counterId = 6)
        metric_id = vim.PerformanceManager.MetricId(counterId=6, instance="")

        # calculate the last 60 seconds
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(seconds=60)

        # Create a query specification for roll-up data
        query_spec = vim.PerformanceManager.QuerySpec(
            entity=vm,
            metricId=[metric_id],
            format="normal",
            startTime=start_time,
            endTime=end_time,
            intervalId=20,  # Use an appropriate interval for the roll-up data
        )


        # Query the performance statistics
        result = perf_manager.QueryStats(querySpec=[query_spec])

        if result:
            # Get the average write IOPS for the last 60 seconds
            average_write_iops = sum(result[0].value[0].value) / len(result[0].value[0].value)
            print(f"Average write IOPS for the last 60 seconds for {vm_name}: {average_write_iops}")
            return average_write_iops
        else:
            return None
        
    def get_average_write_latency(self, vm):
        try:
            content = self.__conn__.RetrieveContent()
        except:
            self.log.debug("Could not get content from vCenter when trying to get VM stats")

        # Find the virtual machine by name
        vm_name = str(vm)
        vm = None

        for obj in content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True).view:
            if obj.name == vm_name:
                vm = obj
                break

        if vm is None:
            self.log.debug(f"Virtual machine '{vm_name}' not found")
            return None

        # Get performance manager
        perf_manager = content.perfManager

        # Define the metric ID for write latency (counterId = X) - replace X with the correct counter ID
        # You'll need to find the specific counter ID for write latency in your vSphere environment.
        # The counter for write latency may vary based on your configuration.

        metric_id = vim.PerformanceManager.MetricId(counterId=10, instance="")  # Replace X with the correct counter ID

        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(seconds=60)

        # Create a query specification for roll-up data
        query_spec = vim.PerformanceManager.QuerySpec(
            entity=vm,
            metricId=[metric_id],
            format="normal",
            startTime=start_time,
            endTime=end_time,
            intervalId=20,  # Use an appropriate interval for the roll-up data
        )

        # Query the performance statistics
        result = perf_manager.QueryStats(querySpec=[query_spec])

        if result:
            # Get the average write latency for the last 60 seconds
            if result[0].value[0].value:
                average_write_latency = sum(result[0].value[0].value) / len(result[0].value[0].value)
                self.log.info(f"Average write latency for the last 60 seconds for {vm_name}: {average_write_latency}")
                return average_write_latency

        return None

    def disconnect(self):
        if self.__conn__ == None:
            self.log.debug(f"vCenter disconnect requested, but not currently connected.")
            return
        # Disconnect from vCenter
        Disconnect(self.__conn__)
        self.__conn__ = None
        self.version = None
        self.log.debug(f"Disconnected from vCenter")