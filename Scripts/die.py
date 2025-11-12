# import die
import pandas as pd
from datetime import datetime
from pathlib import Path
import subprocess
import json
import time
import sys
import filters

__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"

columnNameHash = "Hash"
columnNameAvgEntropy = "Avg_Entropy"
columnNamePacked = "Packed"
log_file_path = "die_output.log"

die_df = pd.DataFrame(columns=[columnNameHash,columnNameAvgEntropy,columnNamePacked])

class Logger:
    def __init__(self):
        self.terminal = sys.__stdout__  
        self.log = open(log_file_path, "a")

    def write(self, message):
        self.terminal.write(message)   
        self.log.write(message)         

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = Logger()


def scan_file(file_path):
    """
    Scan a file using 'diec' tool and return parsed JSON result.
    Args:
        file_path -- Path of the file to scan
    Returns:
        result -- str of information from DIE tool
    """
    try:
        result = subprocess.run(['diec', '-ej',file_path], capture_output=True, text=True, timeout=300)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout!"

def addInfoToDf(die_df,hash,avg_entropy,packed):
    """
    Append a new scan result row to the DIE DataFrame.

    Args:
        die_df -- Existing DataFrame containing DIE scan results.
        hash -- File hash (unique identifier of the scanned binary).
        avg_entropy -- Average entropy value of the binary file.
        packed -- Packing status returned by DIE.

    Returns:
        pd.DataFrame -- Updated DataFrame including the new row.
    """
    die_df = pd.concat([pd.DataFrame([[hash,avg_entropy, packed]], columns=[columnNameHash,columnNameAvgEntropy, columnNamePacked]), die_df], ignore_index=True)
    return die_df


if __name__ == "__main__":
    """
    Main entry point for scanning Mach-O binaries with DIE.
    """
    
    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)
    start_time = time.time()

    die_df = pd.read_csv('../Output/csv/die.csv')
    all_df = pd.read_csv('../Output/csv/src/all_df.csv')  # Load the CSV file containing all hashes

 
    
    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')
    hashes_to_skip_set = set(ios_hashes_df[columnNameHash])
    radare_csv_path = '../Output/csv/src/radare_not_ios.csv'
    radare_df = pd.read_csv(radare_csv_path)

    # Create a dictionary or series for quick lookup of file types by hash
    file_types = dict(zip(radare_df[columnNameHash], radare_df['file_type']))


    for i, entry in enumerate(path.rglob('*')):
        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
        print("Number: ", i, " ",entry.stem, " ", formatted_time)

        if filters.filer_hash_alldata(entry.stem):
            continue

        try: 
            output = scan_file(entry)
            data = json.loads(output)
            packed = data['status']
            avg_entropy = data['total']
            print(packed , " ", avg_entropy)
            die_df = addInfoToDf(die_df,entry.stem,avg_entropy,packed)
        except:
            print("Something went wrong...")

    end_time = time.time()  
    elapsed_time = end_time - start_time 
    print(f"Elapsed time: {elapsed_time}")  
    die_df.to_csv('../Output/csv/src/die.csv', index=False)