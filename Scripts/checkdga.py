import pandas as pd
import os
from pathlib import Path


malware_samples = "../Output/csv/Network/src/basicNetwork.csv"
dns_info = "../Output/csv/Network/src/dns_counts.csv"
dga_folder = "../Output/csv/Network/src/dga/"

def checkdga():
    df = pd.read_csv(dns_info)
    all_domains = set()

    for domains in df['DNS_LOOKUP'].dropna():
        clean_domains = domains.strip("[]").replace("'", "").split(",")
        all_domains.update(domain.strip().lower() for domain in clean_domains)  # also normalize to lowercase


    # Load all DGA domains from files in the /dga folder
    dga_domains = set()
    

    for file in os.listdir(dga_folder):
        if file.endswith(".csv"):
            dga_df = pd.read_csv(os.path.join(dga_folder, file))
            dga_domains.update(dga_df['domain'].str.lower().values)

    dga_hits = all_domains.intersection(dga_domains)

    print(f"[+] Found {len(dga_hits)} domains in DGA lists.")
    for domain in sorted(dga_hits):
        print(domain)

    pd.Series(sorted(dga_hits)).to_csv("../Output/csv/Network/dga_matched_domains.csv", index=False, header=["domain"])


    return 0




checkdga()
