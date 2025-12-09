"""
Format:

Excluded Ports:
    -   TCP : 3454,2345,3455-3453
        UDP : 3443-2453,34
        Universal : 23,53,6-345 
probe:
    -   name : "NULL"
        protocol : TCP/UDP
        totalwaits: xxx
        tcpwrappedms: 
        rarity : 1-9
        ports: [23,24,35-654]
        sslports:
        fallbacks: ["s1" , "s2" ,,]
        probe_payload: ""
        payload:
        signatures:
            -   type: "match"
                service:"http"
                regex:"..."
                Ignore_case:
                New_line_specifier:
                version:
                    raw: 
                    product: ""
                    vertion_template:
                    info:
                    hostname:
                    operating_system:
                    device_type:
                    cpe:
                        service: ""  /a
                        operating_system:""  /o
                        hadware_platform:"" /h
            -   type: "softmatch"
                    service:""
                    regex:".."
                    options: "s/i/both"
                version:
                    raw: 
                    product: ""
                    vertion_template:
                    info:
                    hostname:
                    operating_system:
                    device_type:
                    cpe:
                        service: ""  /a
                        operating_system:""  /o
                        hadware_platform:"" /h 
"""


import yaml
import codecs
def parse_excluded(line):
    line=line.strip()
    if not line:
        return []
    if(line.startswith("Exclude")):
        line = line[len("Exclude"):].strip()
    if not line:
        return []
    parts = [p.strip() for p in line.split(",") if p.strip()]
    tcp_spec =[]
    udp_spec =[]
    universal_spec=[]
    for p in parts:
        if(":" in p):
            proto,spec = p.split(":",1)
            proto = proto.upper()
        else :
            proto,spec = "",p
        
        if proto == "T":
            tcp_spec.append(spec)
        elif proto == "U":
            udp_spec.append(spec)
        else :
            universal_spec.append(spec)
    return {
        "TCP": ",".join(tcp_spec),
        "UDP": ",".join(udp_spec),
        "Universal": ",".join(universal_spec),
    }
    
def parse_ports(line):
    line=line.strip()
    if not line:
        return []
    if(line.startswith("ports")):
        line=line[len("ports"):].strip()
    if not line:
        return []
    parts = [p.strip() for p in line.split(',') if p.strip()]
    final_list=[]
    for p in parts:
        if '-' in p:
            start,end = p.split('-')
            for ports in range (int(start),int(end)+1):
                final_list.append(ports)
        else:
            final_list.append(int(p))
    return final_list
            
def parse_ssl_ports(line):
    line=line.strip()
    if not line:
        return []
    if(line.startswith("sslports")):
        line=line[len("sslports"):].strip()
    if not line:
        return []
    parts = [p.strip() for p in line.split(',') if p.strip()]
    final_list=[]
    for p in parts:
        if '-' in p:
            start,end = p.split('-')
            for ports in range (int(start),int(end)+1):
                final_list.append(ports)
        else:
            final_list.append(int(p))
    return final_list


def parse_probe_file(in_path):
    global excluded_ports
    global probes
    probes=[]
    excluded_ports=[]
    curr_probe=None
    
    with open(in_path , "r" , encoding="utf-8") as f:
        count=0
        for raw_line in f:
            count=count+1
            print("line",count)
            line = raw_line.rstrip("\n")

            if not line or line.lstrip().startswith("#"):
                continue
            
            if line.startswith("Exclude"):
                excluded_ports = parse_excluded(line)
                
            if line.startswith("Probe"):
                if curr_probe is not None:
                    probes.append(curr_probe)
                    
                line = line[len("Probe "):]
                protocol = line[:3]
                line = line[4:]
                
                name = line[0:line.find(" ",0)]
                
                line = line[len(name)+1:]
                
                if line[0] != 'q':
                    KeyError
                
                line = line[1:]
                delim=line[0:1]
                line = line[1:]
                probe_string="\""
                probe_string = line[0:line.find(delim,0)]
                line = line[len(probe_string)+1:]
                line=line.strip()
                if line:
                    no_pay = True
                else:
                    no_pay = False
                
                curr_probe = {
                    "name":name,
                    "protocol": protocol,
                    "totalwaits":5000,
                    "tcpwrappedms":5000,
                    "rarity":5,
                    "ports":[],
                    "sslports":[],
                    "fallbacks":[],
                    "probe_string":probe_string,
                    "no_payload":no_pay,
                    "signatures":[]
                }
                continue
            if curr_probe is None:
                continue
            
            line = line.strip()
            if line.startswith("totalwaitms"):
                _, val = line.split(None, 1)
                curr_probe["totalwaits"] = int(val)
                continue
            if line.startswith("tcpwrappedms"):
                _,val = line.split(None,1)
                curr_probe["tcpwrappedms"] = int(val)
                continue
            
            if line.startswith("rarity"):
                _,val = line.split(None,1)
                curr_probe["rarity"] = int(val)
                continue
            if line.startswith("ports"):
                _,val = line.split(None,1)
                curr_probe["ports"] = parse_ports(line)
                continue
            if line.startswith("sslports"):
                _,val = line.split(None,1)
                curr_probe["sslports"] = parse_ssl_ports(line)
                continue
            
            if line.startswith("fallback"):
                parts = line.split()
                fb = [p.strip() for p in parts[1:] if p.strip()]
                curr_probe["fallbacks"].extend(fb)
                continue
            line = line.strip()
            if line.startswith("match") or line.startswith("softmatch"):
                sig_type = "match" if line.startswith("match") else "softmatch"
                line = line[len(sig_type)+1:]
                service = line[0:line.find(" ",0)]
                line = line[len(service):]
                line=line.strip()
                line=line[1:]
                delimiter = line[0:1]
                line = line[1:]
                regex = line[0:line.find(delimiter,0)]
                line = line[len(regex)+1:]
                options = ""
                while line and line[0]!=' ' and line[0]!='\n':
                    options+=line[0]
                    line=line[1:]
                new_line_specifier=False
                Ignore_case = False
                
                for c in options:
                    if c == 's':
                        new_line_specifier=True
                    if c == 'i':
                        Ignore_case = True
                line = line.strip()
                rest = line
                version_ = ""
                product = ""
                info = ""
                hostname = ""
                operating_system = ""
                device_type = ""
                cpe_service = ""
                cpe_operating_system = ""
                cpe_hardware_platform = ""
                while line:
                    line=line.strip()
                    print(f"character is {sig_type} {service} and {line[0]} and line {count} with options {options} and regex {regex}")
                    if line[0] == 'p':
                        delim1 = line[1:2]
                        line=line[2:]
                        product = line[0:line.find(delim1,0)]
                        line=line[len(product)+1:]
                        line = line.strip()
                    elif line[0] == 'v':
                        delim2 = line[1:2]
                        line=line[2:]
                        version_ = line[0:line.find(delim2,0)]
                        line=line[len(version_)+1:]
                        line = line.strip()
                    elif line[0] == 'i':
                        delim3 = line[1:2]
                        line=line[2:]
                        info = line[0:line.find(delim3,0)]
                        line=line[len(info)+1:]
                        line = line.strip()
                    elif line[0] == 'h':
                        delim4 = line[1:2]
                        line=line[2:]
                        hostname = line[0:line.find(delim4,0)]
                        line=line[len(hostname)+1:]
                        line = line.strip()
                    elif line[0] == 'o':
                        delim5 = line[1:2]
                        line=line[2:]
                        operating_system = line[0:line.find(delim5,0)]
                        line=line[len(operating_system)+1:]
                        line = line.strip()
                    elif line[0] == 'd':
                        delim6 = line[1:2]
                        line=line[2:]
                        device_type = line[0:line.find(delim6,0)]
                        line=line[len(device_type)+1:]
                        line = line.strip()
                    elif line[0:3] == "cpe":
                        line = line[4:]
                        delim7 = line[0:1]
                        line = line[1:]
                        if line[0] == 'h':
                            cpe_hardware_platform = line[2:line.find(delim7,1)]
                            line=line[len(cpe_hardware_platform)+4:]
                        elif line[0] == 'a':
                            cpe_service = line[2:line.find(delim7,1)]
                            line=line[len(cpe_service)+4:]
                        elif line[0] == 'o':
                            cpe_operating_system = line[2:line.find(delim7,1)]
                            line=line[len(cpe_operating_system)+4:]
                        
                sig={
                    "type":sig_type,
                    "service":service,
                    "regex":regex,
                    "Ignore_case":Ignore_case,
                    "New_line_specifier":new_line_specifier,
                    "version":{
                        "raw": rest,
                        "product":product,
                        "version_template":version_,
                        "info":info,
                        "hostname":hostname,
                        "operating_device":operating_system,
                        "device_type":device_type,
                        "cpe":{
                            "cpe_service":cpe_service,
                            "cpe_os":cpe_operating_system,
                            "cpe_h":cpe_hardware_platform,
                        }
                    }
                }
                curr_probe["signatures"].append(sig)
                continue
            
        if curr_probe is not None:
            probes.append(curr_probe)
            
    return probes
                       


def write_yaml(probes, out_path):
    data={
        "Excluded ports":[excluded_ports],
        "probes":probes,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
        
if __name__ == "__main__":
    in_file = "nmap-service-probes.txt"
    out_file = "probes.yaml"
    probes = parse_probe_file(in_file)
    write_yaml(probes, out_file)     
            
