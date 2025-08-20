import pandas as pd
#!/usr/bin/env python
import sys
import r2pipe
import json
import pandas as pd
from pathlib import Path
import time
import re
import os
import subprocess
from datetime import datetime
import commonMethods  # File

columnNamePacked = "Packed"
columnNameHash = "Hash"

# Column names for DataFrame
columnNameHash = "Hash"
columnNameComplexity = "Complexity"
columnNameSize = "Size"
columnNameStripped = "Stripped"
columnNameTotalSymbols = "N_Symbols"
columnNameAvgEntropy = "Avg_Entropy"
columnNameLanguage = "Language"
columnNameCpuType = "cpu_type"
columnNameFile_type = "file_type"
columnNameCount = "Count"

csv_path = '../Output/csv/langs.csv'


def is_macho_binary(file_path):
    """Check if the file is a Mach-O binary"""
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    return 'application/x-mach-binary' in result.stdout




def getInfo(r):
    """Get info in the binary"""
    try:
        symbols = r.cmd('ij')  # Get list of imported symbols
        data = json.loads(symbols)
        print(data)
        return data
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting symbols: {e}")
        return []


def getLang(hash, info, csv_path):
    """see info"""
    try:
        lang = info['bin']['lang']
        if lang:
            with open(csv_path, mode='a') as file:
                file.write(f"{hash},{lang}\n")
    except Exception as e:
        with open(csv_path, mode='a') as file:
            file.write(f"{hash},error\n")
        print(f"Error getting Lang: {e}")
        return "nan"

  




if __name__ == "__main__":
    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)

    
    columns = [columnNameHash, columnNameLanguage]
    if not os.path.exists(csv_path):
        pd.DataFrame(columns=columns).to_csv(csv_path, mode='w', header=True, index=False)

    start_radare_time = time.time()
    output_dir = '../Output/Hashes_info/VT_JSON'

    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')

    hashes_to_skip_set = set(ios_hashes_df[columnNameHash])
   
   

    
    for i, entry in enumerate(path.rglob('*')):
        file_hash = entry.stem
        
        if file_hash in hashes_to_skip_set:  # Skip iOS hashes and hashes that already are created
            continue
        
        symbols = None
        start_time = time.time()
        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')

        print("Number: ", i, " ", entry.stem, " ", formatted_time)


        try:
            if is_macho_binary(entry):
                print("ismacho")
                r = r2pipe.open(str(entry))
                
                info = getInfo(r)
                getLang(entry.stem, info, csv_path)

            else:
                print("isNOTmacho")

            r.quit()
        except Exception as e:
            print(f"Error occurred in the analysis of {entry}: {e}")
            # Ensure we add a newline to the CSV even if there's an error

            r.quit()

        del symbols
        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_radare_time  # Calculate elapsed time in seconds
        print(f"Elapsed time going...: ", i, " ", {elapsed_time})

