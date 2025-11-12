import pandas as pd
import r2pipe
import json
import pandas as pd
from pathlib import Path
import time
import os
import subprocess
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
columnNameLanguage = "Language"
columnNameFile_type = "file_type"
columnNameCount = "Count"
columnNameSymbol = "Symbol"

csv_path_filetype = '../Output/csv/filetype.csv'
csv_path_lang = '../Output/csv/langs.csv'
symbols_csv_path = '../Output/csv/symbols_new.csv'


def radareSymbols():
    """
    Process symbol counts from CSV, aggregate, and save sorted results.
    """
    symbols_df = pd.read_csv('../Output/csv/symbols_new.csv', header=None, on_bad_lines='skip', low_memory=False)

    symbols_df['Count'] = pd.to_numeric(symbols_df['Count'], errors='coerce')
    symbols_df = symbols_df.dropna(subset=['Count'])
    grouped_symbols_df = symbols_df.groupby('Symbol', as_index=False)['Count'].sum()
    grouped_symbols_df = grouped_symbols_df.sort_values(by='Count', ascending=False)
    grouped_symbols_df.to_csv('../Output/csv/symbols_modified.csv', index=False)


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


def countSymbols(symbols, symbols_csv_path):
    """
    Append number of results to a CSV file.

    Args:
        symbols -- List of symbol dictionaries.
        symbols_csv_path -- Path to the output CSV file.

    """
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



def is_macho_binary(file_path):
    """
    Check if a given file is a Mach-O binary.

    Args:
        file_path -- Path to the file.

    Returns:
        bool: True if the file is a Mach-O binary, False otherwise.
    """
    result = subprocess.run(['file', '--mime-type', '-b', file_path], capture_output=True, text=True)
    return 'application/x-mach-binary' in result.stdout


def getInfo(r):
    """
    Retrieve information about a binary using r2pipe.

    Args:
        r -- r2pipe object for the binary.

    Returns:
        dict -- Parsed JSON data with binary info, or an empty list on error.
    """
    try:
        symbols = r.cmd('ij')  # Get list of imported symbols
        data = json.loads(symbols)
        print(data)
        return data
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error getting symbols: {e}")
        return []


def getFiletype(hash, info, csv_path):
    """
    Save the detected file type for a binary to a CSV.

    Args:
        hash -- File hash identifier.
        info -- Info dictionary extracted from the binary.
        csv_path -- Path to the output CSV file.

    Returns:
        str: Detected file type, or "nan" if unavailable.
    """
    try:
        file_type = info['core']['type']
        if file_type:
            with open(csv_path, mode='a') as file:
                file.write(f"{hash},{file_type}\n")
    except Exception as e:
        with open(csv_path, mode='a') as file:
            file.write(f"{hash},error\n")
        print(f"Error getting filetype: {e}")
        return "nan"


def getLang(hash, info, csv_path):
    """
    Save the detected language type for a binary to a CSV.

    Args:
        hash -- File hash identifier.
        info -- Info dictionary extracted from the binary.
        csv_path -- Path to the output CSV file.

    Returns:
        str -- Detected language, or "nan" if unavailable.
    """
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
    """
    Main execution: iterate through binaries, check Mach-O type,
    and record file types, language and symbols using r2pipe into a CSV file.
    """

    binary_dir = '/mnt/DATASETS/macho-binaries-and-reports/binaries/'
    path = Path(binary_dir)

    
    columns = [columnNameHash, columnNameFile_type]
    if not os.path.exists(csv_path_filetype):
        pd.DataFrame(columns=columns).to_csv(csv_path_filetype, mode='w', header=True, index=False)
    
    columns = [columnNameHash, columnNameLanguage]
    if not os.path.exists(csv_path_lang):
        pd.DataFrame(columns=columns).to_csv(csv_path_lang, mode='w', header=True, index=False)

    columns = [columnNameSymbol, columnNameCount]
    if not os.path.exists(symbols_csv_path):
        pd.DataFrame(columns=columns).to_csv(symbols_csv_path, mode='w', header=True, index=False)   

    
    for i, entry in enumerate(path.rglob('*')):
        file_hash = entry.stem
        

        try:
            if is_macho_binary(entry):
                print("ismacho")
                r = r2pipe.open(str(entry))
                
                info = getInfo(r)
                getFiletype(entry.stem, info, csv_path_filetype)
                getLang(entry.stem, info, csv_path_lang)
                symbols = getAllSymbols(r)
                countSymbols(symbols, symbols_csv_path)

            else:
                print("isNOTmacho")

            r.quit()
        except Exception as e:
            print(f"Error occurred in the analysis of {entry}: {e}")
            r.quit()
        del symbols

    radareSymbols()