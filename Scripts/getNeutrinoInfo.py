import json
from pathlib import Path

N_PATH_DOMAINS    = '../Output/Hashes_info/Neutrino_API/N_DOMAIN_JSON'
N_IP_DOMAINS    = '../Output/Hashes_info/Neutrino_API/N_IP_JSON'


info = {
    'is-bot': 0,
    'is-dshield': 0,
    'is-exploit-bot': 0,
    'is-hijacked': 0,
    'is-listed': 0,
    'is-malware': 0,
    'is-proxy': 0,
    'is-spam-bot': 0,
    'is-spider': 0,
    'is-spyware': 0,
    'is-tor': 0,
    'is-vpn': 0,
}
info_domains = {
    'is-adult': 0,
    'is-gov': 0,
    'is-malicious': 0,
    'is-opennic': 0,
    'is-pending': 0,
    'is-subdomain': 0,
}

def getInfoIps():
    global N_IP_DOMAINS
    global info

    N_IP_DOMAINS = Path(N_IP_DOMAINS)
    for i, entry in enumerate(N_IP_DOMAINS.rglob('*')):
        with open(entry) as f:
            data = json.load(f)
            print(data)
            for key in info:
                if data.get(key) is True:
                    info[key] += 1

            
    with open("../Output/csv/Network/Ips_Summary.log", "a") as log:
        log.write(f"{info}")

def getInfoDomains():
    global N_PATH_DOMAINS
    global info_domains

    N_PATH_DOMAINS = Path(N_PATH_DOMAINS)
    for i, entry in enumerate(N_PATH_DOMAINS.rglob('*')):
        with open(entry) as f:
            data = json.load(f)
            print(data)
            for key in info_domains:
                if data.get(key) is True:
                    info_domains[key] += 1

            
    with open("../Output/csv/Network/Domains_Summary.log", "a") as log:
        log.write(f"{info_domains}")
    
getInfoDomains()
getInfoIps()
