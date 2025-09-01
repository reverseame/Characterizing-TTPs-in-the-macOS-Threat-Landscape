#!/usr/bin/env python
import sys
import r2pipe
import json
import pandas as pd
from pathlib import Path
import time
import os
import subprocess
from datetime import datetime
import commonMethods  #File
import filters #File

__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"

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

class Logger:
    """Logger class to write stdout to a file and terminal."""
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
    """
    Get MIME type of a file and write it to CSV.

    Args:
        file_path -- Path to the file.
    """
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    with open(radare_csv_path, mode='a') as file:
        file.write(f",{result.stdout.strip()}\n")


def is_macho_binary(file_path):
    """
    Check if a file is a Mach-O binary.

    Args:
        file_path (str): Path to the file.

    Returns:
        bool: True if Mach-O binary, False otherwise.
    """
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    return 'application/x-mach-binary' in result.stdout


def get_rabin2_arch_info(file_path):
    """
    Get architecture info using rabin2 and append it to CSV.

    Args:
        file_path -- Path to the file.

    Returns:
        str -- Architecture info or 'nan' on error.
    """
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
    """
    Get binary size using radare2.

    Args:
        r -- Open r2pipe object.

    Returns:
        int -- Binary size or 'nan' on error.
    """
    try:
        binaryInfo = r.cmd('ij')
        data = json.loads(binaryInfo)
        size = data.get('bin', {}).get('binsz', 'nan')
        return size
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting size info: {e}")
        return 'nan'
def getStripped(r):
    """
    Check if binary is stripped.

    Args:
        r -- Open r2pipe object.

    Returns:
        str -- '1' if stripped, '0' or 'nan' on error.
    """
    try:
        binaryInfo = r.cmd('ij')
        data = json.loads(binaryInfo)
        stripped = data.get('bin', {}).get('stripped', 'nan')
        return stripped
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting size info: {e}")
        return 'nan'



def getAllSymbols(r):
    """
    Retrieve all imported symbols from a binary.

    Args:
        r -- Open radare2 pipe object.

    Returns:
        list -- Parsed list of symbol dictionaries, or [] on error.
    """
    try:
        symbols = r.cmd('iij')  # Get list of imported symbols
        data = json.loads(symbols)
        return data
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting symbols: {e}")
        return []


def countSymbols(symbols):
    """
    Count the number of symbols to a CSV file.

    Args:
        symbols -- List of symbol dictionaries.
    
    Returns:
        int -- total number of symbols

    """
    total_symbols_count = 0
    try:
        for item in symbols:
            name = item.get('name')
            if name:
                total_symbols_count += 1
    except Exception as e:
        print(f"Error counting symbols: {e}")
        return "nan"
    return total_symbols_count


def tryToGetComplexity(file_hash,existing_complexities,r):
    """
    Get cyclomatic complexity of binary, using cached value if available.

    Args:
        file_hash -- Hash of the binary.
        existing_complexities -- Precomputed complexity values.
        r -- Open r2pipe object.

    Returns:
        float or str -- Complexity value or 'nan' on error.
    """

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



if __name__ == "__main__":
    """
    Analyze Mach-O binaries: size, stripped, number of symbols, complexity, CPU type, and file type.
    Update CSV files with analysis results.
    """
    
    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)

    update = int(sys.argv[1]) 
    if update == 1:
        processed_hashes = set()
        commonMethods.removePath("radare_output.log")
        commonMethods.removePath("../Output/csv/src/radare_not_ios.csv")
 

    columns = [columnNameHash, columnNameSize, columnNameStripped, columnNameTotalSymbols, columnNameComplexity, columnNameCpuType, columnNameFile_type]
    if not os.path.exists(radare_csv_path):
        pd.DataFrame(columns=columns).to_csv(radare_csv_path, mode='w', header=True, index=False)

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


        symbols = None
        start_time = time.time()
        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')

        print("Number: ", i, " ", entry.stem, " ", formatted_time)

        if file_hash not in header_file_type or header_file_type[file_hash] != "Executable file":
            continue
        
        try:
            if is_macho_binary(entry):
                print("ismacho")
                r = r2pipe.open(str(entry))
                

                size = getSize(r)
                stripped = getStripped(r)
                with open(radare_csv_path, mode='a') as file:
                    file.write(f"{entry.stem},{size},{stripped}")

                symbols = getAllSymbols(r)
                total_symbols_count = countSymbols(symbols)
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


    existing_hashes = {entry.stem for entry in Path(binary_dir).rglob('*') if entry.is_file()}


