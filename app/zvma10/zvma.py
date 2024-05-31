import atexit
import threading
import ssl
import json
import os
import time
import logging
import socket
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlencode
from urllib.parse import urlparse
from time import sleep
from datetime import datetime
from dateutil import parser
from typing import List, Dict, Tuple, Union, Any, Optional
from requests.structures import CaseInsensitiveDict
from logging.handlers import RotatingFileHandler
#from posthog import Posthog
import uuid
from requests import Request, Session
from .version import VERSION

class zvmsite:
    def __init__(self, host, username=None, password=None, port: int = 443, verify_ssl: bool = False, client_id="zerto-client", client_secret=None, grant_type="password", loglevel="debug", logger=None, stats: bool = True) -> None:
        self.stats = stats
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}:{self.port}"

        if not self.verify_ssl:
            # Disable ssl warnings if verify is set to false.
            urllib3.disable_warnings(InsecureRequestWarning)

        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_type = grant_type

        self.__auththread__ = None
        self.__version__ = VERSION
        self.token = None
        self.expiresIn = 0
        self.token_expire_time = None

        self.site_id = None
        self.site_name = None
        self.site_type = None
        self.site_type_version = None

        self.zvm_version = dict(full=None, major=None, minor=None, update=None, patch=None)

        self.__user_agent_string__ = f"zerto_python_sdk_jpaul"

        self.apiheader = CaseInsensitiveDict()
        self.apiheader["Accept"] = "application/json"
        self.apiheader['User-Agent'] = self.__user_agent_string__

        self.__connected__ = False
        self._running = False
        self.LOGLEVEL = loglevel.upper()
        
        if logger is None:
            self.setup_logging()
        else:
            self.log = logger

        atexit.register(self.disconnect)
        self._running = True

        # Get UUID
        self.uuid = self.load_or_generate_uuid()

        # Posthog stats setup
        #if self.stats:
        #    self.setup_posthog()
        #    self.posthog.capture(self.uuid, 'ZVMA10 Python Module Loaded')
        #    self.log.debug("Sent PostHog Hook")

    def __authhandler__(self) -> None:
        self.log.info(f"Log Level set to {self.LOGLEVEL}")
        if not self.__connected__:
            context = ssl.create_default_context()
            if not self.verify_ssl:
                self.log.debug("Disabling SSL verification")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            retries = 0
            while self._running:
                if self.expiresIn < 30:
                    self.log.debug(f"Authenticating to the server: {self.host}")
                    headers = CaseInsensitiveDict()
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

                    data = {
                        "grant_type": self.grant_type,
                        "client_id": self.client_id
                    }
                    if self.grant_type == "client_credentials":
                        data["client_secret"] = self.client_secret
                    else:
                        data["username"] = self.username
                        data["password"] = self.password


                    uri = self.construct_url(path="auth/realms/zerto/protocol/openid-connect/token")
                    response = self.make_api_request("POST", uri, data=data, headers=headers)

                    if response and 'access_token' in response and 'expires_in' in response:
                        self.token = str(response['access_token'])
                        self.apiheader["Authorization"] = "Bearer " + self.token
                        self.expiresIn = int(response['expires_in'])
                        self.log.info("Authentication successful")
                        self.__connected__ = True
                        local_site_info = self.local_site()
                        self.site_id = local_site_info['SiteIdentifier']
                        self.site_name = local_site_info['SiteName']
                        
                    else:
                        self.log.error("Authentication failed")
                        sleep(2 ** retries)
                        retries += 1
                else:
                    sleep(10)
                    self.expiresIn -= 10
        else:
            self.log.info("Authentication thread is already running")
            print(f"Auth thread already running")

    def is_authenticated(self) -> bool:
        # Assuming self.token is the authentication token and it's set upon successful authentication
        # and self.__connected__ is a boolean indicating the connection status
        return self.token is not None and self.__connected__
    
    def setup_logging(self) -> None:
        container_id = str(socket.gethostname())
        log_formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(threadName)s;%(message)s", "%Y-%m-%d %H:%M:%S")
        log_handler = RotatingFileHandler(filename=f"./logs/Log-{container_id}.log", maxBytes=1024*1024*100, backupCount=5)
        log_handler.setFormatter(log_formatter)
        self.log = logging.getLogger("ZVM10 Module")
        self.log.setLevel(self.LOGLEVEL)
        self.log.addHandler(log_handler)

    def __redact__(self, data) -> str:
        sensitive_keys = ["password", "secret", "token"]  # Add any other keys that need redaction
        redacted_data = {}

        for key, value in data.items():
            if key in sensitive_keys:
                redacted_data[key] = "********"
            else:
                redacted_data[key] = value

        return redacted_data

    def load_or_generate_uuid(self) -> uuid.uuid4:
        uuid_path = 'uuid.txt'
        if os.path.exists(uuid_path):
            with open(uuid_path, 'r') as file:
                saved_uuid = file.read().strip()
                try:
                    return str(uuid.UUID(saved_uuid))
                except ValueError:
                    pass  # Invalid UUID, generate a new one below
        
        new_uuid = str(uuid.uuid4())
        with open(uuid_path, 'w') as file:
            file.write(new_uuid)
        return new_uuid

    #def setup_posthog(self)  -> None:
    #    self.posthog = Posthog(project_api_key='phc_HflqUkx9majhzm8DZva8pTwXFRnOn99onA9xPpK5HaQ', host='https://posthog.jpaul.io')
    #    self.posthog.debug = True
    #    self.posthog.identify(distinct_id=self.uuid)

    def construct_url(self, path="", params=None) -> str:
        full_url = f"{self.base_url}/{path}"
        if params:
            query_string = urlencode({k: str(v) for k, v in params.items() if v is not None})
            full_url = f"{full_url}?{query_string}"
        return full_url

    def deconstruct_url(self, url) -> Tuple[str, str]:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path

        return base_url, path
    
    def make_api_request(self, method, url, data=None, json_data=None, headers=None, timeout=3, test=None) -> Optional[Union[Dict[str, Any], str]]:
        try:
            headers = headers or {}
            start_time = time.time()  # Record the start time
            if method == "PUT":
                # Create a Request object
                headers['Content-Type'] = 'application/json'
                data = json.dumps(json_data)
                req = Request(method, url, data=data, headers=headers)

                # Prepare the request
                prepared_req = req.prepare()

                # Print the prepared request details
                self.log.debug("Prepared Request:")
                self.log.debug(f"URL: {prepared_req.url}")
                self.log.debug(f"Method: {prepared_req.method}")
                self.log.debug(f"Headers: {prepared_req.headers}")
                self.log.debug(f"Body: {prepared_req.body}")

                # Send the request using a Session
                with Session() as s:
                    response = s.send(prepared_req, verify=self.verify_ssl)

                # Print the response
                self.log.debug(f"Response Status Code: {response.status_code}")
                self.log.debug(response.text)
            elif json_data is not None:
                # If json_data is provided, serialize it as JSON and set the appropriate header
                serialized_data = json.dumps(json_data)
                headers['Content-Type'] = 'application/json'
                self.log.debug(f"API Request using JSON Body: {serialized_data}")
                response = requests.request(method, url, data=serialized_data, headers=headers, timeout=timeout, verify=self.verify_ssl)
            else:
                # If json_data is not provided, use data as-is
                if data:
                    self.log.debug(f"API Request using Form/Data Body: {self.__redact__(data)}")
                response = requests.request(method, url, data=data, headers=headers, timeout=timeout, verify=self.verify_ssl)

            end_time = time.time()
            elapsed_time_ms = (end_time - start_time) * 1000
            response.raise_for_status()
            self.log.debug(f'API Request: {method} - {url}')

            # Posthog stats setup
            #if self.stats:
            #    temp_base, temp_path = self.deconstruct_url(url)
            #    self.posthog.capture( self.uuid, 'API REQUEST',
            #    {
            #        "url": temp_base,
            #        "port": self.port,
            #        "endpoint": temp_path,
            #        "method": method,
            #        "response_time_ms": int(elapsed_time_ms),
            #        "verify_ssl": self.verify_ssl, 
            #        "grant_type": self.grant_type,
            #        "status_code": str(response.status_code),
            #        "sdk_version": self.__version__
            #    })
            #    self.log.debug("Sent PostHog Hook")

            return response.json()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error while sending API request: {e}")
            if e.response:
                self.log.error(f"Response content: {e.response.text}")
            return None

    def connect(self) -> None:
        if (self.__auththread__ is None) or (not self.__auththread__.is_alive()):
            self._running = True
            self.__auththread__ = threading.Thread(target=self.__authhandler__, daemon=True)
            self.__auththread__.start()
            self.log.info(f"Starting authentication thread {self.__auththread__.ident}")
        else:
            self.log.info("Already connected to the ZVM")

    def disconnect(self) -> None:
        self.log.debug("Disconnecting")
        self._running = False
        if self.__auththread__ and self.__auththread__.is_alive():
            self.__auththread__.join(timeout=5) 
     
    def alert(self, alertidentifier=None) -> Dict[str, Any]:
        
        if alertidentifier is None:
            self.log.error("Alert identifier is required for get_vpg function.")
            raise ValueError("Alert identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/alerts/{alertidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
          
    def alert_dismiss(self, alertidentifier=None) -> bool:
        if alertidentifier is None:
            self.log.error("Alert identifier is required for alert_dismiss function.")
            raise ValueError("Alert identifier is required.")

        params = {}
        uri = self.construct_url(f"v1/alerts/{alertidentifier}/dismiss", params)

        try:
            response = self.make_api_request("POST", uri, headers=self.apiheader)
            # Check if the response status code is 200 (OK)
            if response.status_code == 200:
                return True
            else:
                # Log and raise an exception for any non-200 status codes
                self.log.error(f"Failed to dismiss alert: {response.status_code}")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error while sending dismiss alert request: {e}")
            raise

        return False  # Return False if the try block didn't execute successfully

    def alert_undismiss(self, alertidentifier=None) -> bool:
        if alertidentifier is None:
            self.log.error("Alert identifier is required for alert_undismiss function.")
            raise ValueError("Alert identifier is required.")

        params = {}
        uri = self.construct_url(f"v1/alerts/{alertidentifier}/undismiss", params)

        try:
            response = self.make_api_request("POST", uri, headers=self.apiheader)
            # Check if the response status code is 200 (OK)
            if response.status_code == 200:
                return True
            else:
                # Log and raise an exception for any non-200 status codes
                self.log.error(f"Failed to undismiss alert: {response.status_code}")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error while sending undismiss alert request: {e}")
            raise

        return False  # Return False if the try block didn't execute successfully
      
    def alerts(self, startdate=None, enddate=None, vpgid=None, zorgidentifier=None, level=None, 
             entity=None, helpidentifier=None, isdismissed: bool = None) -> List[Dict[str, Any]]:
        
        params = {
            'startdate': startdate,
            'enddate': enddate,
            'vpgid': vpgid,
            'zorgidentifier': zorgidentifier,
            'level': level,
            'entity': entity,
            'helpidentifier': helpidentifier,
            'isdismissed': isdismissed
        }
        
        uri = self.construct_url("v1/alerts", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
        
    def alert_levels(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/alerts/levels", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
           
    def alert_entities(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/alerts/entities", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
                 
    def alert_helpidentifiers(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/alerts/helpidentifiers", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def datastore(self, datastoreidentifier=None) -> Dict[str, Any]:
        
        if datastoreidentifier is None:
            self.log.error("Datastore identifier is required for get_datastore function.")
            raise ValueError("datastore identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/datastores/{datastoreidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
 
    def datastores(self, datadtoreidentifier=None) -> List[Dict[str, Any]]:
        
        params = {
        }
        
        uri = self.construct_url("v1/datastores", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def datetime_local(self) -> datetime:
        params = {}
        uri = self.construct_url(f"v1/serverDateTime/serverDateTimeLocal", {})
        response = self.make_api_request("GET", uri, headers=self.apiheader)

        if response is not None:
            # Extract the datetime string from the JSON response
            return parser.isoparse(response)
        else:
            error_message = "API request failed or returned None"
            self.log.error(error_message)
            raise ValueError(error_message)
    
    def datetime_utc(self,) -> datetime:
        params = {}
        uri = self.construct_url(f"v1/serverDateTime/serverDateTimeUtc", params)
        response = self.make_api_request("GET", uri, headers=self.apiheader)

        if response is not None:
            # Extract the datetime string from the JSON response
            return parser.isoparse(response)
        else:
            error_message = "API request failed or returned None"
            self.log.error(error_message)
            raise ValueError(error_message)
    
    def datetime_check(self, dt_str: str) -> datetime:
        try:
            # Try to parse the string into a datetime object
            dt = parser.isoparse(dt_str)
        except ValueError:
            # If parsing fails, raise an error
            raise ValueError("The 'dt_str' parameter must be a valid datetime string.")

        # Format the datetime object for the API call
        formatted_datetime = dt.isoformat()

        params = {'datetime': formatted_datetime}

        # Construct the URL with the datetime argument
        uri = self.construct_url(f"v1/serverDateTime/dateTimeArgument", params)

        # Make the API request
        response = self.make_api_request("GET", uri, headers=self.apiheader)

        # Check if the response is not None and parse the datetime string
        if response is not None:
            return parser.isoparse(response)
        else:
            error_message = "API request failed or returned None"
            self.log.error(error_message)
            raise requests.exceptions.HTTPError(error_message)

    def encryptiondetection_enable(self):
                
        params = {
            "encryptionDetectionEnabled": True
        }
        
        uri = self.construct_url("v1/encryptionDetection/state", params)
        return self.make_api_request("POST", uri, headers=self.apiheader)

    def encryptiondetection_disable(self):
                
        params = {
            "encryptionDetectionEnabled": False
        }
        
        uri = self.construct_url("v1/encryptionDetection/state", params)
        return self.make_api_request("POST", uri, headers=self.apiheader)

    def encryptiondetection_status(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/state", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_metrics_vms(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/metrics/vms", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_metrics_volumes(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/metrics/volumes", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_metrics_vpgs(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/metrics/vpgs", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_suspected_vms(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/suspected/vms", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_suspected_volumes(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/suspected/volumes", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def encryptiondetection_suspected_vpgs(self):
                
        params = {}
        
        uri = self.construct_url("v1/encryptionDetection/suspected/vpgs", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def event(self, eventidentifier=None) -> Dict[str, Any]:
        
        if eventidentifier is None:
            self.log.error("Event identifier is required for get event function.")
            raise ValueError("Event identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/events/{eventidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
      
    def events(self, startdate=None, enddate=None, vpgid=None, sitename=None, zorgidentifier=None, eventtype=None, 
             entitytype=None, category=None, username=None, alertidentifier=None) -> List[Dict[str, Any]]:
        
        params = {
            'startdate': startdate,
            'enddate': enddate,
            'vpgid': vpgid,
            'sitename': sitename,
            'zorgidentifier': zorgidentifier,
            'eventtype': eventtype,
            'entitytype': entitytype,
            'category': category,
            'username': username,
            'alertidentifier': alertidentifier
        }
        
        uri = self.construct_url("v1/events", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
                   
    def event_types(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/events/types", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
           
    def event_entities(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/events/entities", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
                 
    def event_categories(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/events/categories", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
                  
    def license(self) -> Dict[str, Any]:

        params = {
        }
        
        uri = self.construct_url(f"v1/license", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def license_delete(self) -> bool:
        params = {}
        uri = self.construct_url(f"v1/license", params)

        try:
            response = self.make_api_request("DELETE", uri, headers=self.apiheader)
            # Check if the response status code is 200 (OK)
            if response.status_code == 200:
                return True
            else:
                # Log and raise an exception for any non-200 status codes
                self.log.error(f"Failed to delete license: {response.status_code}")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error while sending license delete request: {e}")
            raise

        return False  # Return False if the try block didn't execute successfully

    def license_apply(self, license=None):
        if license is None:
            self.log.error("A license key is required for apply license function.")
            raise ValueError("License key is required.")

        params = {
        }

        license = {
            "licenseKey": license
        }

        uri = self.construct_url(f"v1/license", params)
        return self.make_api_request("PUT", uri, json_data=license, headers=self.apiheader)
  
    def local_site(self) -> Dict[str, Any]:

        params = {
        }
        
        uri = self.construct_url(f"v1/localsite", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def local_site_pairing_statues(self):

        params = {
        }
        
        uri = self.construct_url(f"v1/localsite/pairingstatuses", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def local_site_send_billing(self) -> bool:
        params = {}
        uri = self.construct_url(f"v1/localsite/settings/sendusage", params)

        try:
            response = self.make_api_request("POST", uri, headers=self.apiheader)
            # Check if the response status code is 200 (OK)
            if response.status_code == 200:
                return True
            else:
                # Log and raise an exception for any non-200 status codes
                self.log.error(f"Failed to send billing information: {response.status_code}")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error while sending billing information request: {e}")
            raise

        return False  # Return False if the try block didn't execute successfully

    def local_site_banner(self) -> Dict[str, Any]:

        params = {
        }
        # uri is spelled incorrectly because it is also spelled incorrectly in zerto
        uri = self.construct_url(f"v1/localsite/settings/logingbanner", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def local_site_banner_update(self, enabled: bool = None, loginbanner = None):

        params = {
        }

        data = {
            "isLoginBannerEnabled": enabled,
            "loginBanner": loginbanner
        }
        # uri is spelled incorrectly because it is also spelled incorrectly in zerto
        uri = self.construct_url(f"v1/localsite/settings/logingbanner", params)
        return self.make_api_request("PUT", uri, json_data=data, headers=self.apiheader)

    def peer_sites(self) -> List[Dict[str, Any]]:

        params = {
        }
        
        uri = self.construct_url(f"v1/peersites", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def peer_site(self, siteidentifier=None) -> Dict[str, Any]:
        if siteidentifier is None:
            self.log.error("Site identifier is required for get site function.")
            raise ValueError("Site identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/peersites/{siteidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
          
    def peer_sites_pairing_statues(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/peersites/pairingstatuses", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
        
    def peer_site_add(self, hostname=None, port=None, token=None):
        missing_params = [param for param, value in [('hostname', hostname), ('port', port), ('token', token)] if value is None]
        
        if missing_params:
            missing_params_str = ", ".join(missing_params)
            error_message = f"Missing required parameter(s): {missing_params_str} for pair site function."
            self.log.error(error_message)
            raise ValueError(error_message)

        params = {}

        data = {
            "hostname": hostname,
            "port": port,
            "token": token
        }

        uri = self.construct_url(f"v1/peersites", params)
        return self.make_api_request("POST", uri, json_data=data, headers=self.apiheader)   

    def peer_site_delete(self, siteidentifier=None, keepdisks: bool = True):
        if siteidentifier is None:
            self.log.error("Site identifier is required for delete site function.")
            raise ValueError("Site identifier is required.")

        params = {}

        data = {
            "iskeeptargetdisks": keepdisks
        }
        
        uri = self.construct_url(f"v1/peersites/{siteidentifier}", params)
        return self.make_api_request("DELETE", uri, json=data, headers=self.apiheader)
    
    def peer_site_pairing_token(self) -> Dict[str, Any]:
        params = {}

        uri = self.construct_url(f"v1/peersites/generatetoken", params)
        return self.make_api_request("POST", uri, headers=self.apiheader)   

    def recovery_reports(self, starttime=None, endtime=None, pagenumber=None, pagesize=None, vpgname=None, recoverytype=None, state=None) -> List[Dict[str, Any]]:
        
        params = {
            'starttime': starttime,
            'endtime': endtime,
            'pagenumber': pagenumber,
            'pagesize': pagesize,
            'vpgname': vpgname,
            'recoverytype': recoverytype,
            'state': state
        }
        
        uri = self.construct_url("v1/reports/recovery", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def recovery_report(self, recoveryoperationidentifier=None) -> Dict[str, Any]:
        
        if recoveryoperationidentifier is None:
            self.log.error("RecoveryOperationIdentifier is required for function.")
            raise ValueError("RecoveryOperationIdentifier is required.")

        params = {}
        
        uri = self.construct_url(f"v1/reports/recovery/{recoveryoperationidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def resources_report(self, starttime=None, endtime=None, pagenumber=None, pagesize=None, zorgname=None, vpgname=None, vmname=None, 
                         protectedsitename=None, protectedclustername=None, protectedhostname=None, protectedorgvdc=None, protectedvcdorg=None, recoverysitename=None, 
                         recoveryclustername=None, recoveryhostname=None, recoveryorgvdc=None, recoveryvcdorg=None) -> List[Dict[str, Any]]:
        
        params = {
            'starttime': starttime,
            'endtime': endtime,
            'pagenumber': pagenumber,
            'pagesize': pagesize,
            'vpgname': vpgname,
            'vmname': vmname,
            'protectedsitename': protectedsitename,
            'protectedclustername': protectedclustername,
            'protectedhostname': protectedhostname,
            'protectedorgvdc': protectedorgvdc,
            'protectedvcdorg': protectedvcdorg,
            'recoverysitename': recoverysitename,
            'recoveryclustername': recoveryclustername,
            'recoveryhostname': recoveryhostname,
            'recoveryorgvdc': recoveryorgvdc,
            'recoveryvcdorg': recoveryvcdorg
        }
        
        uri = self.construct_url("v1/reports/resources", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def service_profiles(self) -> List[Dict[str, Any]]:

        params = {
        }
        
        uri = self.construct_url(f"/v1/serviceprofiles", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def service_profile(self, serviceProfileIdentifier=None) -> Dict[str, Any]:
        if siteidentifier is None:
            self.log.error("Service Profile identifier is required for get site function.")
            raise ValueError("Service Profile identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"/v1/serviceprofiles/{serviceProfileIdentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def tasks(self, startedbeforedate=None, startedafterdate=None, completedbeforedate=None, completedafterdate=None, tasktype=None, status=None) -> List[Dict[str, Any]]:
        
        params = {
            'startedbeforedate': startedbeforedate,
            'startedafterdate': startedafterdate,
            'completedbeforedate': completedbeforedate,
            'completedafterdate': completedafterdate,
            'type': tasktype,
            'status': status
        }
        
        uri = self.construct_url("v1/tasks", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
     
    def task(self, taskidentifier=None) -> Dict[str, Any]:
        
        if taskidentifier is None:
            self.log.error("Task identifier is required for function.")
            raise ValueError("Task identifier is required.")

        params = {}
        
        uri = self.construct_url(f"v1/tasks/{taskidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
                
    def task_types(self) -> List[str]:

        params = {
        }
        
        uri = self.construct_url(f"v1/tasks/types", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vms_statistics(self) -> List[Dict[str, Any]]:
        
        params = { }
        
        uri = self.construct_url("v1/statistics/vms", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
 
    def vms(self, vmidentifier=None, vmname=None, vpgstatus=None, vpgsubstatus=None, protectedsitetype=None, 
             recoverysitetype=None, protectedsiteidentifier=None, recoverysiteidentifier=None, 
             zorgname=None, priority=None, includebackupvms: bool = None, includemountedvms: bool = None) -> List[Dict[str, Any]]:
        
        params = {
            'vmidentifier': vmidentifier,
            'vmname': vmname,
            'vpgstatus': vpgstatus,
            'vpgsubstatus': vpgsubstatus,
            'protectedsitetype': protectedsitetype,
            'recoverysitetype': recoverysitetype,
            'protectedsiteidentifier': protectedsiteidentifier,
            'recoverysiteidentifier': recoverysiteidentifier,
            'zorgname': zorgname,
            'priority': priority,
            'includebackupvms': includebackupvms,
            'includemountedvms': includemountedvms
        }
        
        uri = self.construct_url("v1/vms", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vm(self, vmidentifier=None, vpgidentifier=None, includebackupvms: bool = None, includemountedvms: bool = None):
        
        if vmidentifier is None:
            self.log.error("VM identifier is required for get_vm function.")
            raise ValueError("VM identifier is required.")

        params = {
            'vpgidentifier': vpgidentifier,
            'includebackupvms': includebackupvms,
            'includemountedvms': includemountedvms
        }
        
        uri = self.construct_url(f"v1/vms/{vmidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
    
    def vm_pointintime(self, vmidentifier=None, vpgidentifier=None, includebackupvms: bool = None, includemountedvms: bool = None):
        
        if vmidentifier is None:
            self.log.error("VM identifier is required for vm_pointintime function.")
            raise ValueError("VM identifier is required for vm_pointintime.")

        params = {
            'vpgidentifier': vpgidentifier,
            'includebackupvms': includebackupvms,
            'includemountedvms': includemountedvms
        }
        
        uri = self.construct_url(f"v1/vms/{vmidentifier}/pointsintime", params)
        stats = self.make_api_request("GET", uri, headers=self.apiheader)   

        if isinstance(stats, list) and not stats:
            self.log.error("No points in time found for the specified VM. Or the VM is in Multiple VPGs, try specifing vpgidentifier.")
            raise ValueError("No points in time found for the specified VM. Or the VM is in Multiple VPGs, try specifing vpgidentifier.")
        elif stats is None:
            self.log.error("VM not found, or vpgidentifier must be specified")
            raise ValueError("VM not found, or vpgidentifier must be specified")
        else:
            return stats

    def vm_pointintime_stats(self, vmidentifier=None, vpgidentifier=None):
        
        if vmidentifier is None:
            self.log.error("VM identifier is required for get_vm function.")
            raise ValueError("VM identifier is required.")

        params = {
            'vpgidentifier': vpgidentifier
        }
        
        uri = self.construct_url(f"v1/vms/{vmidentifier}/pointsInTime/stats", params)
        stats = self.make_api_request("GET", uri, headers=self.apiheader)   

        if stats is None:
            self.log.error("VM not found, or vpgidentifier must be specified")
            raise ValueError("VM not found, or vpgidentifier must be specified")
        else:
            return stats

    def volumes(self, volumetype=None, vpgidentifier=None, datastoreidentifier=None, protectedvmidentifier=None, owningvmidentifier=None) -> List[Dict[str, Any]]:
        if volumetype:
            valid_volumetypes = ["scratch", "journal", "recovery", "protected", "appliance"]
            
            # Convert volumetype to lowercase for case-insensitive comparison
            volumetype_lower = volumetype.lower()

            if volumetype_lower not in valid_volumetypes:
                raise ValueError(f"Invalid volumetype: {volumetype}. Must be one of {', '.join(valid_volumetypes)}")

        params = {
            'volumetype': volumetype,
            'vpgidentifier': vpgidentifier,
            'datastoreidentifier': datastoreidentifier,
            'protectedvmidentifier': protectedvmidentifier,
            'owningvmidentifier': owningvmidentifier
        }
        
        uri = self.construct_url("v1/volumes", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg(self, vpgidentifier=None) -> Dict[str, Any]:
        
        if vpgidentifier is None:
            self.log.error("Vpg identifier is required for get_vpg function.")
            raise ValueError("VM identifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vpgs/{vpgidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_checkpoints(self, vpgidentifier=None) -> Dict[str, Any]:
        
        if vpgidentifier is None:
            self.log.error("Vpg identifier is required for vpg_checkpoints function.")
            raise ValueError("vpgidentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vpgs/{vpgidentifier}/checkpoints", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_take_checkpoint(self, vpgidentifier=None, checkpointname=None) -> Dict[str, Any]:
        
        if vpgidentifier is None:
            self.log.error("Vpg identifier is required for vpg_checkpoints function.")
            raise ValueError("vpgidentifier is required.")
        
        # Construct the JSON payload
        json_payload = {"checkpointname": "Checkpoint By Python ZVM Module"}
        if checkpointname is not None:
            json_payload["checkpointname"] = checkpointname

        params = { }
        
        uri = self.construct_url(f"v1/vpgs/{vpgidentifier}/checkpoints", params)
        return self.make_api_request("POST", uri, json_data=json_payload, headers=self.apiheader)

    def vpg_checkpoint_stats(self, vpgidentifier=None) -> Dict[str, Any]:
        
        if vpgidentifier is None:
            self.log.error("Vpg identifier is required for vpg_checkpoints function.")
            raise ValueError("vpgidentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vpgs/{vpgidentifier}/checkpoints/stats", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
         
    def vpgs(self, vpgid=None, vpgname=None, vpgstatus=None, vpgsubstatus=None, protectedsitetype=None, 
             recoverysitetype=None, protectedsiteidentifier=None, recoverysiteidentifier=None, 
             zorgidentifier=None, priority=None, serviceprofileidentifier=None) -> List[Dict[str, Any]]:
        
        params = {
            'vpgid': vpgid,
            'vpgname': vpgname,
            'vpgstatus': vpgstatus,
            'vpgsubstatus': vpgsubstatus,
            'protectedsitetype': protectedsitetype,
            'recoverysitetype': recoverysitetype,
            'protectedsiteidentifier': protectedsiteidentifier,
            'recoverysiteidentifier': recoverysiteidentifier,
            'zorgidentifier': zorgidentifier,
            'priority': priority,
            'serviceprofileidentifier': serviceprofileidentifier
        }
        
        uri = self.construct_url("v1/vpgs", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
    
    def vpg_delete(self, vpgidentifier=None, keeprecoveryvolumes=True, force=True):
        if vpgidentifier is None:
            self.log.error("VPG identifier is required for delete_vpg function.")
            raise ValueError("VPG identifier is required.")

        # URL with vpgidentifier in the path
        uri = self.construct_url(f"v1/vpgs/{vpgidentifier}")

        # Data to be sent in the request body
        data = {
            "keepRecoveryVolumes": keeprecoveryvolumes,
            "force": force
        }

        # Make the POST request
        return self.make_api_request("POST", uri, data=data, headers=self.apiheader)

    def vpg_retention_policies(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/retentionpolicies", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_priorities(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/priorities", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
 
    def vpg_entity_types(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/entitytypes", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_statuses(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/statuses", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
 
    def vpg_substatuses(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/substatuses", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_failover_shutdown_policies(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/failovershutdownpolicies", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vpg_failover_commit_policies(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vpgs/failovercommitpolicies", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vras(self, vraname=None, status=None, vraversion=None, hostname=None, ipaddress=None, 
             vragroup=None, datastorename=None, datastoreclustername=None, networkname=None, vraipconfigurationapi=None) -> List[Dict[str, Any]]:
        
        params = {
            'vraname': vraname,
            'status': status,
            'vraversion': vraversion, 
            'hostname': hostname,
            'ipaddress': ipaddress, 
            'vragroup': vragroup,
            'datastorename': datastorename,
            'datastoreclustername': datastoreclustername,
            'networkname': networkname,
            'vraipconfigurationapi': vraipconfigurationapi
        }
        
        uri = self.construct_url(f"v1/vras", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vra(self, vraidentifier=None) -> Dict[str, Any]:
         
        if vraidentifier is None:
            self.log.error("vraidentifier is required for vra function.")
            raise ValueError("vraidentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vras/{vraidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vra_upgrade(self, vraidentifier=None) -> Dict[str, Any]:
         
        if vraidentifier is None:
            self.log.error("vraidentifier is required for vra function.")
            raise ValueError("vraidentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vras/{vraidentifier}/upgrade", params)
        return self.make_api_request("POST", uri, headers=self.apiheader)

    def vra_statuses(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vras/statuses", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def vra_ipconfigurationtypes(self) -> List[str]:

        params = {}
        
        uri = self.construct_url(f"v1/vras/ipconfigurationtypes", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    """
    def vra_cluster_settings(self, clusteridentifier=None) -> Dict[str, Any]:
         
        if clusteridentifier is None:
            self.log.error("clusteridentifier is required for vra function.")
            raise ValueError("clusteridentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/vras/clusters/{clusteridentifier}/settings", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)
    """

    def zorgs(self) -> Dict[str, Any]:
    
        params = {
        }
        
        uri = self.construct_url(f"v1/zorgs", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def zorg(self, zorgidentifier=None) -> Dict[str, Any]:
             
        if zorgidentifier is None:
            self.log.error("zorgidentifier is required for function.")
            raise ValueError("zorgidentifier is required.")

        params = {
        }
        
        uri = self.construct_url(f"v1/zorgs/{zorgidentifier}", params)
        return self.make_api_request("GET", uri, headers=self.apiheader)

    def __set_zvm_version__(self) -> None:
        uri = self.construct_url("v1/localsite")
        response = self.make_api_request("GET", uri, headers=self.apiheader)
        if response:
            self.site_id = str(response.get('SiteIdentifier', ''))
            self.site_name = str(response.get('SiteName', ''))
            self.zvm_version['full'] = str(response.get('Version', ''))
            self.site_type_version = str(response.get('SiteTypeVersion', ''))
            self.site_type = str(response.get('SiteType', ''))

            # Break out ZVM version strings
            version_parts = self.zvm_version['full'].split(".")
            if len(version_parts) >= 3:
                self.zvm_version['major'], self.zvm_version['minor'], temp = version_parts
                self.zvm_version['update'] = temp[0]
                self.zvm_version['patch'] = temp[1] if len(temp) > 1 else "0"
            self.log.info(f"Site ID: {self.site_id}, Site Name: {self.site_name}, Site Type: {self.site_type}")

    def version(self) -> Dict[str, Any]:
        if self.__connected__ and self._running:
            if self.zvm_version['full'] is None:
                self.__set_zvm_version__()
            return self.zvm_version
        else:
            return "Error: Not Connected to ZVM"
