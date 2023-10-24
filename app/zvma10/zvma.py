# Class for holding variables related to a site.

class site:
    def __init__(self):
        self.zvm_ip = None
        self.zvm_port = 443
        self.zvm_client = None
        self.zvm_secret = None
        self.zvm_verify_ssl = False
        self.zvm_token = None
        self.id = None
        self.name = None
        self.zvm_version = None
        self.zvm_version_major = None
        self.zvm_version_minor = None
        self.zvm_version_update = None
        self.zvm_version_patch = None

        self.vc_ip = None
        self.vc_port = 443
        self.vc_username = None
        self.vc_password = None
        self.vc_verify_ssl = False
        self.vc_version = None


    # ZVM Related Set / Get Functions
    def set_zvm_ip(self, value):
        self.zvm_ip = value

    def set_zvm_port(self, value):
        self.zvm_port = value

    def set_zvm_client(self, value):
        self.client = value

    def set_zvm_secret(self, value):
        self.zvm_secret = value

    def set_zvm_verify_ssl(self, value):
        self.zvm_verify_ssl = value

    def set_zvm_token(self, value):
        self.set_zvm_token = value

    def set_zvm_id(self, value):
        self.id = value

    def set_zvm_name(self, value):
        self.zvm_name = value

    def set_zvm_version(self, value):
        # Set main zvm version variable
        self.zvm_version = value

        # Break out ZVM version string into Major, Minor, Update, Patch variables
        self.zvm_version_major, self.zvm_version_minor, temp = self.zvm_version.split(".")
        self.zvm_version_update = temp[0]
        if (len(temp) > 1):
            self.zvm_version_patch = temp[1]
        else:
            self.zvm_version_patch = "0"

    def set_zvm_token(self, value):
        self.set_zvm_token = value

    def get_zvm_ip(self):
        return self.zvm_ip

    def get_zvm_port(self):
        return self.zvm_port
    
    def get_zvm_username(self):
        return self.zvm_username
    
    def get_zvm_password(self):
        return self.zvm_password
    
    def get_zvm_token(self):
        return self.zvm_token
    

    # vCenter related Get / Set Functions