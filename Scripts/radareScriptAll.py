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

log_file_path = "radare_output.log"
radare_csv_path = '../Output/csv/src/radare_not_ios.csv'
symbols_csv_path = '../Output/csv/symbols.csv'

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


def get_file_type(file_path):
    """Get file MIME type"""
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    with open(radare_csv_path, mode='a') as file:
        file.write(f",{result.stdout.strip()}\n")


def is_macho_binary(file_path):
    """Check if the file is a Mach-O binary"""
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    return 'application/x-mach-binary' in result.stdout


def get_rabin2_arch_info(file_path):
    """Get architecture information using rabin2"""
    try:
        result = subprocess.run(['rabin2', '-jA', file_path], capture_output=True, text=True, check=True)
        arch_info = json.loads(result.stdout)
        arch_bits_list = []

        if arch_info and 'bins' in arch_info:
            bins = arch_info['bins']
            for bin_info in bins:
                arch_bits = f"{bin_info['arch']}_{bin_info['bits']}"
                arch_bits_list.append(arch_bits)

        concatenated_arch_bits = " ".join(arch_bits_list) if arch_bits_list else "unknown"
        print("concatenated_arch_bits: ", concatenated_arch_bits)
        with open(radare_csv_path, mode='a') as file:
            file.write(f",{concatenated_arch_bits}".encode('utf-8', 'replace').decode('utf-8'))

    except subprocess.CalledProcessError as e:
        print(f"Error getting architecture info for {file_path}: {e}")
        return "nan"
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response for {file_path}: {e}")

        return "nan"



def getSize(r):
    try:
        binaryInfo = r.cmd('ij')
        data = json.loads(binaryInfo)
        size = data.get('bin', {}).get('binsz', 'nan')
        return size
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting size info: {e}")
        return 'nan'
def getStripped(r):
    try:
        binaryInfo = r.cmd('ij')
        data = json.loads(binaryInfo)
        stripped = data.get('bin', {}).get('stripped', 'nan')
        return stripped
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting size info: {e}")
        return 'nan'



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


def tryToGetComplexity(file_hash,existing_complexities,r):

    if file_hash in existing_complexities:
        complexity = existing_complexities[file_hash]
        print(f"Complexity from existing file: {complexity}")
        return complexity
    else:
        try:
            r.cmd('e anal.timeout = {}'.format(300))
            r.cmd('aa') 
            complexity = float(r.cmd('afCc'))  # Cyclomatic complexity
            print(complexity)
            return complexity
        except Exception as e:
            print(f"Error getting complexity: {e}")
            return 'nan'
        

def detectiOShashes(output_dir,ios_hashes_df):
    path = Path(output_dir)
    hashes_to_skip_set = set(ios_hashes_df[columnNameHash])
    total_items = sum(1 for entry in path.rglob('*') if entry.stem not in hashes_to_skip_set)

    start_time = time.time()
    for i, entry in enumerate(path.rglob('*')):
        commonMethods.custom_progress_bar("Progress getInfoAboutEachBinary, " ,i + 1, total_items,start_time)
        file_hash = entry.stem
        if file_hash in hashes_to_skip_set: #Skip ios hashes
            continue
        
        with open(entry) as f:
            data = json.load(f)
            try:
                output_file = "../Output/csv/src/iOShashes.csv"
                has_ios_tag = 'ios' in data['data']['attributes'].get('tags', [])
                if has_ios_tag:
                    print("ES IOS este: ", entry.stem)
                    with open(output_file, 'a') as out_file:
                        out_file.write(f"{entry.stem}\n")
            except:
                print("Not found anything")
                pass



if __name__ == "__main__":
    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)

    update = int(sys.argv[1]) 
    if update == 1:
        processed_hashes = set()
        commonMethods.removePath("radare_output.log")
        commonMethods.removePath("../Output/csv/src/radare_not_ios.csv")
        commonMethods.removePath('../Output/csv/symbols.csv')
 

    columns = [columnNameHash, columnNameSize, columnNameStripped, columnNameTotalSymbols, columnNameComplexity, columnNameCpuType, columnNameFile_type]
    if not os.path.exists(radare_csv_path):
        pd.DataFrame(columns=columns).to_csv(radare_csv_path, mode='w', header=True, index=False)

    columns = [columnNameSymbol, columnNameCount]
    if not os.path.exists(symbols_csv_path):
        pd.DataFrame(columns=columns).to_csv(symbols_csv_path, mode='w', header=True, index=False)

    start_radare_time = time.time()
    output_dir = '../Output/Hashes_info/VT_JSON'

    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')
    detectiOShashes(output_dir,ios_hashes_df)
    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')

    radare_df = pd.read_csv(radare_csv_path)

    complexity_df = pd.read_csv('../Output/csv/src/complexity_info.csv')
    existing_complexities = dict(zip(complexity_df[columnNameHash], complexity_df[columnNameComplexity]))

    
    # Load existing hashes to skip duplicates
    if os.path.exists(radare_csv_path):
        processed_hashes = set(pd.read_csv(radare_csv_path)[columnNameHash])
    else:
        processed_hashes = set()


    header_file_type_df_path = '../Output/csv/src/filetype.csv'
    header_file_type_df = pd.read_csv(header_file_type_df_path)
    header_file_type = dict(zip(header_file_type_df[columnNameHash], header_file_type_df['FileType']))#executable
    
    for i, entry in enumerate(path.rglob('*')):
        file_hash = entry.stem
        
        # if filters.filer_hash_alldata(file_hash):
        #     continue
        if file_hash not in header_file_type or header_file_type[file_hash] != "Executable file":
            continue
        
        if file_hash in processed_hashes:
            continue
            
        if file_hash == "fc564f33364b38eadac3203c1acfe39f":
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
                

                size = getSize(r)
                stripped = getStripped(r)
                with open(radare_csv_path, mode='a') as file:
                    file.write(f"{entry.stem},{size},{stripped}")

                symbols = getAllSymbols(r)
                total_symbols_count = countSymbols(symbols, symbols_csv_path)
                with open(radare_csv_path, mode='a') as file:
                    file.write(f",{total_symbols_count}".encode('utf-8', 'replace').decode('utf-8'))

                complexity = tryToGetComplexity(entry.stem,existing_complexities,r)
                with open(radare_csv_path, mode='a') as file:
                    file.write(f",{complexity}")

                get_rabin2_arch_info(entry)
                get_file_type(entry)
                r.quit()
            else:
                print("isNOTmacho")
                with open(radare_csv_path, mode='a') as file:
                    file.write(f"{entry.stem},nan,nan,nan,nan")
                get_rabin2_arch_info(entry)
                get_file_type(entry)
                r.quit()

            
        except Exception as e:
            print(f"Error occurred in the analysis of {entry}: {e}")
            # Ensure we add a newline to the CSV even if there's an error
            with open(radare_csv_path, mode='a') as file:
                file.write(f"\n")
                file.write(f"{entry.stem},nan,nan,nan,nan,nan")
            get_file_type(entry)
            # r.quit()

        del symbols
        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_radare_time  # Calculate elapsed time in seconds
        print(f"Elapsed time going...: ", i, " ", {elapsed_time})

    existing_hashes = {entry.stem for entry in Path(binary_dir).rglob('*') if entry.is_file()}


