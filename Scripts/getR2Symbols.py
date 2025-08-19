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
import filters
columnNamePacked = "Packed"
columnNameHash = "Hash"

# Column names for DataFrame
columnNameHash = "Hash"
columnNameComplexity = "Complexity"
columnNameSize = "Size"
columnNameStripped = "Stripped"
columnNameTotalSymbols = "N_Symbols"
columnNameAvgEntropy = "Avg_Entropy"
columnNameSymbol = "Symbol"
columnNameCpuType = "cpu_type"
columnNameFile_type = "file_type"
columnNameCount = "Count"

symbols_csv_path = '../Output/csv/symbols_new.csv'

def radareSymbols():
    symbols_df = pd.read_csv('../Output/csv/symbols_new.csv', header=None, on_bad_lines='skip', low_memory=False)

    # Rename columns for clarity
    symbols_df.columns = ['Symbol', 'Count']

    symbols_df['Count'] = pd.to_numeric(symbols_df['Count'], errors='coerce')

    # Drop any rows where 'Count' is NaN (originally non-integer or missing values)
    symbols_df = symbols_df.dropna(subset=['Count'])

    # Group by 'Symbol' and sum the 'Count' for each unique symbol
    grouped_symbols_df = symbols_df.groupby('Symbol', as_index=False)['Count'].sum()

    # Sort by count in descending order
    grouped_symbols_df = grouped_symbols_df.sort_values(by='Count', ascending=False)
    grouped_symbols_df.to_csv('../Output/csv/symbols_modified.csv', index=False)



def is_macho_binary(file_path):
    """Check if the file is a Mach-O binary"""
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    return 'application/x-mach-binary' in result.stdout




def getAllSymbols(r):
    """Get all symbols in the binary"""
    try:
        symbols = r.cmd('iij')  # Get list of imported symbols
        data = json.loads(symbols)
        return data
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting symbols: {e}")
        return []


def countSymbols(symbols, symbols_csv_path):
    """Count symbols and write them to CSV"""
    total_symbols_count = 0
    try:
        for item in symbols:
            name = item.get('name')
            if name:
                count = 1
                with open(symbols_csv_path, mode='a') as file:
                    file.write(f"{name},{count}\n")
                total_symbols_count += 1
    except Exception as e:
        print(f"Error counting symbols: {e}")
        return "nan"
    return total_symbols_count

  




if __name__ == "__main__":
    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)

    
    columns = [columnNameSymbol, columnNameCount]
    if not os.path.exists(symbols_csv_path):
        pd.DataFrame(columns=columns).to_csv(symbols_csv_path, mode='w', header=True, index=False)

    start_radare_time = time.time()
    output_dir = '../Output/Hashes_info/VT_JSON'

    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')

   
   

    
    for i, entry in enumerate(path.rglob('*')):
        file_hash = entry.stem
        symbols = None
        start_time = time.time()
        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')

        print("Number: ", i, " ", file_hash, " ", formatted_time)
        if filters.filer_hash_alldata(file_hash):
            continue
        
        

        

        try:
            if is_macho_binary(entry):
                print("ismacho")
                r = r2pipe.open(str(entry))
                
                symbols = getAllSymbols(r)
                total_symbols_count = countSymbols(symbols, symbols_csv_path)

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

    radareSymbols()