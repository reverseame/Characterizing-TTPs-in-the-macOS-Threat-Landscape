import json
from pathlib import Path

VT_PATH_DOMAINS    = '../Output/Hashes_info/VT_DOMAINS_JSON'
VT_IP_DOMAINS    = '../Output/Hashes_info/VT_IP_JSON'



def getInfoReportsVT(path,path_out,name):

    with open(path_out, "a") as file:
        file.write(name + ',' + 'Malicious'+'\n')

    path = Path(path)
    for i, entry in enumerate(path.rglob('*')):
        with open(entry) as f:
            data = json.load(f)
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            result = False
            if malicious_count >=5:
                result = True
            with open(path_out, "a") as file:
                file.write(entry.stem + ',' + str(result)+'\n')
                # for key in info:
                #     if data.get(key) is True:
                #         info[key] += 1

path_ip= "../Output/csv/Network/malicious_ips.csv"
name_ip = "Ips"
path_domain= "../Output/csv/Network/malicious_domains.csv"
name_domain = "Domains"
getInfoReportsVT(VT_IP_DOMAINS,path_ip,name_ip)
getInfoReportsVT(VT_PATH_DOMAINS,path_domain,name_domain)
