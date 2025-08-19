# import die
import pandas as pd
from datetime import datetime
from pathlib import Path
import subprocess
import json
import time
import sys
import filters
columnNameHash = "Hash"
columnNameAvgEntropy = "Avg_Entropy"
columnNamePacked = "Packed"

log_file_path = "die_output.log"

die_df = pd.DataFrame(columns=[columnNameHash,columnNameAvgEntropy,columnNamePacked])

# print(die.scan_file("/bin/ls", die.ScanFlags.Deepscan)) NO FUNCIONA LA API (LIBRARIA DIE)
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
    try:
        result = subprocess.run(['diec', '-ej',file_path], capture_output=True, text=True, timeout=300)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout!"

def addInfoToDf(die_df,hash,avg_entropy,packed):
    die_df = pd.concat([pd.DataFrame([[hash,avg_entropy, packed]], columns=[columnNameHash,columnNameAvgEntropy, columnNamePacked]), die_df], ignore_index=True)
    return die_df


if __name__ == "__main__":
        
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