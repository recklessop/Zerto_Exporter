# Class for holding variables related to a site.
#from pyVim.connect import SmartConnect, Disconnect
#from pyVmomi import vim, vmodl
import threading
import atexit
import ssl
import datetime
import logging
import requests
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.structures import CaseInsensitiveDict
from logging.handlers import RotatingFileHandler

class zvmsite:
    def __init__(self, host, username=None, password=None, port=443, verify_ssl=False, client_id="zerto-client", client_secret=None, grant_type="password", loglevel="debug"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.uri = "https://" + str(self.host) + ":" + str(self.port)

        self.client_id = client_id
        self.client_secret = None
        self.grant_type = grant_type

        self.__auththread__ = None
        self.token = None
        self.expiresIn = 0
        self.token_expire_time = None

        self.site_id = None
        self.site_name = None
        self.site_type = None
        self.site_type_version = None

        self.zvm_version = dict(
            full=None,
            major=None,
            minor=None,
            update=None,
            patch=None
        )

        self.api_version = dict(
            major = None,
            minor = None,
            update = None
        )

        self.apiheader = CaseInsensitiveDict()
        self.apiheader["Accept"] = "application/json"

        self.__connected__ = False
        self._running = False
        self.LOGLEVEL = loglevel.upper()

        #set log line format including container_id
        log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")
        log_handler = RotatingFileHandler(filename=f"./logs/Log-Main-vcenter.log", maxBytes=1024*1024*100, backupCount=5)
        log_handler.setFormatter(log_formatter)
        self.log = logging.getLogger("Node-Exporter")
        self.log.setLevel(self.LOGLEVEL)
        self.log.addHandler(log_handler)

        atexit.register(self.terminate)
        self._running = True
      
    def terminate(self): 
        self.log.debug("Terminating other threads")
        self._running = False
        self.__auththread__.join()

    def connect(self):
        if (self.__auththread__ == None) or (not self.__auththread__.is_alive()):
            self._running = True
            self.__auththread__ = threading.Thread(target=self.__authhandler__)
            self.__auththread__.start()
            self.log.info(f"Starting authentication thread {self.__auththread__.ident}")
        else:
            self.log.info("Already connected to the ZVM")
    

    def __authhandler__(self):
        self.log.info(f"Log Level set to {self.LOGLEVEL}")
        if not self.__connected__:
            context = ssl.create_default_context()
            if not self.verify_ssl:
                print("dont verify SSL")
                # Create an SSL context without certificate verification
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            try:
                # connect to zvm Server
                retries = 0
                while self._running:
                    if self.expiresIn < 30:
                        self.log.debug(f"Trying login with the following: grant_type: {self.grant_type}, username: {self.username}, password: {self.password}, client_id: {self.client_id}")
                        h = CaseInsensitiveDict()
                        h["Content-Type"] = "application/x-www-form-urlencoded"

                        d = CaseInsensitiveDict()
                        d["grant_type"] = self.grant_type
                        if self.grant_type == "password":
                            d["client_id"] = self.client_id
                            d["username"] = self.username
                            d["password"] = self.password
                        elif self.grant_type == "client_credentials":
                            d["client_id"] = self.client_id
                            d["client_secret"] = self.client_secret
                        else:
                            self.__connected__ = False
                            self.log.error(f"Error connection credentials not defined")
                                        
                        uri = "https://" + str(self.host) + ":" + str(self.port) + "/auth/realms/zerto/protocol/openid-connect/token"
                        delay = 0

                        try:
                            response = requests.post(url=uri, data=d, headers=h, verify=self.verify_ssl)
                            response.raise_for_status()
                        except requests.exceptions.RequestException as e:
                            retries += 1
                            delay = 2 ** retries
                            self.log.error("Error while sending authentication request: " + str(e) + ". Retrying in " + str(delay) + " seconds")
                            sleep(delay)
                            continue
                        else:
                            retries = 0
                        
                        responseJSON = response.json()
                        if 'access_token' not in responseJSON or 'expires_in' not in responseJSON:
                            self.log.error("Authentication response does not contain expected keys")
                            delay = 2 ** retries
                            self.__connected__ = False
                            sleep(delay)
                            retries += 1
                            continue
                        
                        self.token = str(responseJSON.get('access_token'))
                        self.apiheader["Authorization"] = "Bearer " + self.token
                        self.expiresIn = int(responseJSON.get('expires_in'))
                        self.log.info("Authentication successful. Token expires in " + str(self.expiresIn) + " seconds")
                        self.__connected__ = True

                        if response.status_code != 200:
                            self.log.error("Authentication request failed with status code " + str(response.status_code))
                            delay = 2 ** retries
                            self.__connected__ = False
                            sleep(delay)
                            retries += 1
                            continue
                            self.log.debug("Connected to ZVM Server %s", self.host)
                    else:
                        if not self._running:
                            self.__auththread__.terminate()
                        self.log.debug(f"Time till token expiration: {self.expiresIn} seconds")
                        self.log.debug(f"Current auth token: {self.token}")
                        sleep(10)
                        self.expiresIn = self.expiresIn - 10

            except Exception as e:
                self.__connected__ = False
                self.log.error(f"Error connecting to ZVM Server: {e}")

    def __set_zvm_version__(self):
        # Get Site ID and Name
        uri = self.uri + "/v1/localsite"
        delay = 0
        try:
            self.log.debug("Getting Site ID and Name")
            
            response = requests.get(url=uri, timeout=3, headers=self.apiheader, verify=self.verify_ssl)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            retries += 1
            delay = 2 ** retries
            self.log.error("Error while sending api request: " + str(e))
        else:
            retries = 0
        
        responseJSON = response.json()
        self.log.debug(responseJSON)
        if 'SiteIdentifier' not in responseJSON or 'SiteName' not in responseJSON:
            self.log.error("LocalSite API response does not contain expected keys")
            delay = 2 ** retries
            #sleep(delay)
            retries += 1
        else:
            self.site_id = str(responseJSON.get('SiteIdentifier'))
            self.site_name = str(responseJSON.get('SiteName'))
            self.zvm_version['full'] = str(responseJSON.get('Version'))
            self.site_type_version = str(responseJSON.get('SiteTypeVersion'))
            self.site_type = str(responseJSON.get('SiteType'))

            # Break out ZVM version strings
            self.zvm_version['major'], self.zvm_version['minor'], temp = self.zvm_version['full'].split(".")
            self.zvm_version['update'] = temp[0]
            if (len(temp) > 1):
                self.zvm_version['patch'] = temp[1]
            else:
                self.zvm_version['patch'] = "0"
            
            self.log.info("Site ID: " + self.site_id + " Site Name: " + self.site_name + " Site Type: " + self.site_type ) 
                 
    def version(self):
        if self.__connected__ and self._running:
            if self.zvm_version['full'] == None:
                self.__set_zvm_version__()
            return self.zvm_version
        else:
            return "Error: Not Connected to ZVM"
    
    '''
    def set_version(self):
        # Set main zvm version variable
        self.zvm_version = value

        # Break out ZVM version string into Major, Minor, Update, Patch variables
        self.zvm_version_major, self.zvm_version_minor, temp = self.zvm_version.split(".")
        self.zvm_version_update = temp[0]
        if (len(temp) > 1):
            self.zvm_version_patch = temp[1]
        else:
            self.zvm_version_patch = "0"


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

    '''

    def disconnect(self):
        if self._running == False:
            self.log.debug(f"ZVM disconnect requested, but not currently connected.")
            return
        
        self.terminate()
        # clear class variables
        self._running = False
        self.__connected__ = False
        self.__auththread__ = None
        self.token = None
        self.expiresIn = 0
        self.token_expire_time = None

        self.site_id = None
        self.site_name = None
        self.site_type = None
        self.site_type_version = None

        self.zvm_version = dict(
             major=None,
             minor=None,
             update=None,
             patch=None
        )

        self.api_version = dict(
            major = None,
            minor = None,
            update = None
        )

        self.log.debug(f"Disconnected from ZVM")