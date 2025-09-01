import pandas as pd
import os
from pathlib import Path

__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"


def check_dga(dns_info,dga_folder,output_file):
    """Check if observed domains match known DGA domains from DGArchive.

    This function loads DNS lookup data, extracts domains,
    normalizes them to lowercase, and compares them against
    known DGA domain lists. Matches are saved to a CSV file.

    Args:
        dns_info (Path): Path to the CSV file containing DNS lookup information in JSON format.
        dga_folder (Path): Path to the folder containing DGA CSV lists.
        output_file (Path): Path to save matched DGA domains.
    """
        

    df = pd.read_csv(dns_info)
    all_domains = set()

    for domains in df['DNS_LOOKUP'].dropna():
        clean_domains = domains.strip("[]").replace("'", "").split(",")
        all_domains.update(domain.strip().lower() for domain in clean_domains) 


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

    pd.Series(sorted(dga_hits)).to_csv(output_file, index=False, header=["domain"])



dns_info = "../Output/csv/Network/src/dns_counts.csv"
dga_folder = "../Output/csv/Network/src/dga/"
output_file = "../Output/csv/Network/dga_matched_domains.csv"
check_dga(dns_info,dga_folder,output_file)
