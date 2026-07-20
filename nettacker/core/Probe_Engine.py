from collections import deque
from nettacker.core.probe_sender import tcp_probe,udp_probe,tcp_probe_ssl
from nettacker.core.utils.probes_loader import version_details
import re 
import string
from nettacker.core.lib.base import BaseEngine, BaseLibrary

P_RE = re.compile(r"\$P\((\d+)\)")

SUBST_RE = re.compile(
    r"""\$SUBST\(
        \s*(\d+)\s*,      # group index
        \s*"([^"]*)"\s*, # old string
        \s*"([^"]*)"\s*  # new string
    \)""",
    re.VERBOSE
)

PLACE_RE = re.compile(r"\$(\d+)")

I_RE = re.compile(
    r"""\$I\(
       \s*(\d+)\s*,
       \s*([<>])\s* 
        \)""",
        re.VERBOSE
)

def I(value: bytes | str, endian: str) -> int:
    """
    Interpret up to 8 bytes as unsigned integer
    endian: '>' = big-endian, '<' = little-endian
    """
    if isinstance(value, str):
        value = value.encode("latin1", errors="ignore")

    value = value[:8]  # limit to 8 bytes

    byteorder = "big" if endian == ">" else "little"
    return int.from_bytes(value, byteorder=byteorder, signed=False)

def P(value: bytes | str) -> str:
    """
    Make a string printable:
    - Remove NULLs
    - Keep only printable ASCII
    """
    if isinstance(value, bytes):
        value = value.decode("latin1", errors="ignore")

    return "".join(ch for ch in value if ch in string.printable and ch != "\x00")

def apply_subst(match_obj, regex_match):
    i = int(match_obj.group(1))
    old = match_obj.group(2)
    new = match_obj.group(3)

    try:
        value = regex_match.group(i)
    except IndexError:
        return ""

    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("latin1", errors="ignore")

    return value.replace(old, new)

def expand_SUBST(template: str, regex_match):
    while True:
        m = SUBST_RE.search(template)
        if not m:
            break
        replacement = apply_subst(m, regex_match)
        template = template[:m.start()] + replacement + template[m.end():]

    return template

def expand_I(template: str, match):
    def repl(m):
        idx = int(m.group(1))
        endian = m.group(2)
        try:
            captured = match.group(idx)
        except IndexError:
            return ""
        return str(I(captured, endian))

    return I_RE.sub(repl, template)

def expand_P(template: str, regex_match):
    def repl(m):
        i = int(m.group(1))
        try:
            return P(regex_match.group(i))
        except IndexError:
            return ""
    return P_RE.sub(repl, template)
    
def expand_place(template: str, regex_match):
    def repl(m):
        i = int(m.group(1))
        try:
            value = regex_match.group(i)
        except IndexError:
            return ""

        if isinstance(value, bytes):
            value = value.decode("latin1", errors="ignore")

        return value

    return PLACE_RE.sub(repl, template)


def expand_template(template: str, regex_match):
    template = expand_SUBST(template, regex_match)
    template = expand_P(template, regex_match)
    template = expand_I(template , regex_match)
    template = expand_place(template , regex_match)
    return template

class result:
    def __init__(self,version_template=None , product=None , info=None ,hostname=None,
                operating_device=None, device_type=None ,
                cpe_service=None , cpe_os=None , cpe_h=None):
        self.version_template = version_template
        self.product = product
        self.info = info
        self.hostname = hostname
        self.operating_device = operating_device
        self.device_type = device_type
        self.cpe_service = cpe_service
        self.cpe_os = cpe_os
        self.cpe_h = cpe_h
        
        
class ProbeEngine(BaseEngine):
    def __init__(self,port ,protocol ,host,probes_by_name):
        self.probes_by_name= probes_by_name
        self.probes = list(probes_by_name.values())
        self.host = host
        self.port = int(port)
        self.protocol = protocol
        
    def get_probes_for_port(self):
        protocol = self.protocol.lower()
        specific = []
        for p in self.probes:
            if p.protocol!=protocol and p.name!="NULL":
                continue
            if self.port in p.ports or p.name=="NULL" or self.port in p.sslports:
                specific.append(p)
        
        return specific
    # todo , sort it as per the rarity order given and compare with input rarity before selection
    # To implement no-payload logic similar to Nmap 
    def get_probes_for_sslport(self):
        protocol = self.protocol.lower()
        specific = []
        for p in self.probes:
            if p.protocol!=protocol and p.name!="NULL":
                continue
            if self.port in p.sslports or p.name=="NULL":
                specific.append(p)
        return specific
    
    def Match_response(self , response , signature):
        if response == None:
            return {"status":False, "result":result()}
        
        if isinstance(response, str):
            response = response.encode("latin-1", errors="ignore")
        regex = signature.regex
        match = regex.search(response)
        if not match:
            return {"status":False, "result":result()}
        
        version_ = signature.version_details
        if version_.version_template != None:
            version_template = expand_template(version_.version_template, match)
        if version_.product != None:
            product          = expand_template(version_.product, match)
        if version_.info != None:
            info             = expand_template(version_.info, match)
        if version_.hostname != None:
            hostname         = expand_template(version_.hostname, match)
        if version_.operating_device != None:
            operating_device = expand_template(version_.operating_device, match)
        if version_.device_type != None:
            device_type      = expand_template(version_.device_type, match)
        if version_.cpe_service != None:
            cpe_service      = expand_template(version_.cpe_service, match)
        if version_.cpe_os != None:
            cpe_os           = expand_template(version_.cpe_os, match)
        if version_.cpe_h != None:
            cpe_h            = expand_template(version_.cpe_h, match)

        return {
            "status":True,
            "result":result(
            version_template=version_template,
            product=product,
            info=info,
            hostname=hostname,
            operating_device=operating_device,
            device_type=device_type,
            cpe_service=cpe_service,
            cpe_os=cpe_os,
            cpe_h=cpe_h,
        )
    }
                
    
    def check_match_service(self, Signatures , service)->bool:
        for sig_ in Signatures:
            if sig_.service == service:
                return True
        return False
            
    def probe_sequentially(self):
        relevant_probes = self.get_probes_for_port()
        
        final_version_info = None  
        detected_service = None    
        ssl_flag = False
        raw_response = b''
        
        for probe in relevant_probes:
            # Check if we should switch to SSL probes
            if detected_service == "ssl" and not ssl_flag:
                relevant_probes = self.get_probes_for_sslport()
                ssl_flag = True
                    
            if self.protocol == "tcp":  
                if not ssl_flag:
                    response = tcp_probe(self.host, self.port, probe.probe_string, probe.totalwaits, probe.tcpwrapperdms)
                else:
                    response = tcp_probe_ssl(self.host, self.port, probe.probe_string, probe.totalwaits, probe.tcpwrapperdms)
            else:
                response = udp_probe(self.host, self.port, probe.probe_string, probe.totalwaits)
            
            if response == None:
                response = tcp_probe(self.host, self.port, probe.probe_string, probe.totalwaits, probe.tcpwrapperdms)
                
           
            if not response or response.get("raw_bytes") is None:
                continue    
            

            raw_response = response.get("raw_bytes")
          
            # 1. Check Primary Signatures
            for signature in probe.Signatures:
                matched_data = self.Match_response(raw_response, signature)
                res_ = matched_data["result"]
                if matched_data["status"]:
                    if signature.sig_type == "match":
                        # Hard match: Return immediately
                        if signature.sig_type == "match":
                            if signature.service!="ssl":
                                logs=[]
                                if(res_.version_template):
                                    logs.append(f"version_template: {res_.version_template}")
                                if(res_.product):
                                    logs.append(f"product: {res_.product}")
                                if(res_.info):
                                    logs.append(f"info: {res_.info}")
                                if(res_.hostname):
                                    logs.append(f"hostname: {res_.hostname}")
                                if(res_.operating_device):
                                    logs.append(f"operating_device: {res_.operating_device}")
                                if(res_.device_type):
                                    logs.append(f"device_type: {res_.device_type}")
                                if(res_.cpe_service):
                                    logs.append(f"cpe_service: {res_.cpe_service}")
                                if(res_.cpe_os):
                                    logs.append(f"cpe_os: {res_.cpe_os}")
                                if(res_.cpe_h):
                                    logs.append(f"cpe_h: {res_.cpe_h}")
                                if(response.get('cipher')):
                                    logs.append(f"cipher: {response.get('cipher')}")
                                if(response.get('tcp_wrapped')):
                                    logs.append(f"tcp_wrapped: {response.get('tcp_wrapped')}")
                                if(response.get('peer_name')):
                                    logs.append(f"peer_name: {response.get('peer_name')}")
                                logs = str(logs)
                                return {
                                    "service": signature.service,
                                    "ssl_flag": response.get("ssl_flag"),
                                    "log":[f"{logs}"]
                                    }
                            else:
                                detected_service = signature.service
                                final_version_info = matched_data["result"]
                    elif signature.sig_type == "softmatch":
                        # Soft match: Note the service and keep probing for version info
                        detected_service = signature.service
                        final_version_info = matched_data["result"]
                        continue

            # 2. Check Fallbacks (Fixing the indentation/logic error)
            for name in probe.fallbacks:
                fallback_probe = self.probes_by_name.get(name)
                if not fallback_probe: continue
                
                for signature in fallback_probe.Signatures:
                    matched_data = self.Match_response(raw_response, signature)
                    if matched_data["status"]:
                        if signature.sig_type == "match":
                            if signature.service!="ssl":
                                logs=[]
                                if(res_.version_template):
                                    logs.append(f"version_template: {res_.version_template}")
                                if(res_.product):
                                    logs.append(f"product: {res_.product}")
                                if(res_.info):
                                    logs.append(f"info: {res_.info}")
                                if(res_.hostname):
                                    logs.append(f"hostname: {res_.hostname}")
                                if(res_.operating_device):
                                    logs.append(f"operating_device: {res_.operating_device}")
                                if(res_.device_type):
                                    logs.append(f"device_type: {res_.device_type}")
                                if(res_.cpe_service):
                                    logs.append(f"cpe_service: {res_.cpe_service}")
                                if(res_.cpe_os):
                                    logs.append(f"cpe_os: {res_.cpe_os}")
                                if(res_.cpe_h):
                                    logs.append(f"cpe_h: {res_.cpe_h}")
                                if(response.get('cipher')):
                                    logs.append(f"cipher: {response.get('cipher')}")
                                if(response.get('tcp_wrapped')):
                                    logs.append(f"tcp_wrapped: {response.get('tcp_wrapped')}")
                                if(response.get('peer_name')):
                                    logs.append(f"peer_name: {response.get('peer_name')}")
                                return {
                                    "service": signature.service,
                                    "ssl_flag": response.get("ssl_flag"),
                                    "log":[f"{logs}"]
                                    }
                            else:
                                detected_service = signature.service
                                final_version_info = matched_data["result"]
                        elif signature.sig_type == "softmatch":
                            detected_service = signature.service
                            final_version_info = matched_data["result"]

        # Final fall-through: if we found a softmatch but no hard match
        if detected_service:
            logs=[]
            if(res_.version_template):
                logs.append(f"version_template: {res_.version_template}")
            if(res_.product):
                logs.append(f"product: {res_.product}")
            if(res_.info):
                logs.append(f"info: {res_.info}")
            if(res_.hostname):
                logs.append(f"hostname: {res_.hostname}")
            if(res_.operating_device):
                logs.append(f"operating_device: {res_.operating_device}")
            if(res_.device_type):
                logs.append(f"device_type: {res_.device_type}")
            if(res_.cpe_service):
                logs.append(f"cpe_service: {res_.cpe_service}")
            if(res_.cpe_os):
                logs.append(f"cpe_os: {res_.cpe_os}")
            if(res_.cpe_h):
                logs.append(f"cpe_h: {res_.cpe_h}")
            if(response.get('cipher')):
                logs.append(f"cipher: {response.get('cipher')}")
            if(response.get('tcp_wrapped')):
                logs.append(f"tcp_wrapped: {response.get('tcp_wrapped')}")
            if(response.get('peer_name')):
                logs.append(f"peer_name: {response.get('peer_name')}")
            return {
                "service": detected_service,
                "ssl_flag": ssl_flag,
                "log":[f"{logs}"]
                }
        
        return None

            
