import pandas as pd


__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"

columnNameHash = "Hash"
radare_csv_path = '../Output/csv/src/radare_not_ios.csv'
radare_df = pd.read_csv(radare_csv_path)
file_types = dict(zip(radare_df[columnNameHash], radare_df['file_type']))#x-mach-binary
header_file_type_df_path = '../Output/csv/src/filetype.csv'
header_file_type_df = pd.read_csv(header_file_type_df_path)
header_file_type = dict(zip(header_file_type_df[columnNameHash], header_file_type_df['FileType']))#executable
sandbox_df_path = '../Output/csv/src/sandbox_df.csv'
sandboxes_df = pd.read_csv(sandbox_df_path)
sandboxes_types = dict(zip(sandboxes_df[columnNameHash], sandboxes_df['Sandbox']))#3 virustotal sandboxes
ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')

def filer_hash_alldata(hash):
    """
    Check whether a file hash should be skipped based on type, header, or iOS tag.

    Args:
        hash -- File hash identifier.

    Returns:
        bool: True if the file should be skipped, False otherwise.
    """
    if hash not in file_types or file_types[hash] != "application/x-mach-binary":
        return True  # Skip files that do not match the 'application/x-mach-binary' type

    if hash not in header_file_type or header_file_type[hash] != "Executable file":
        return True  # Skip files that do not match the 'EXECUTABLE' type in the header

    if hash in ios_hashes_df[columnNameHash].values:
        return True
    
    return False

def filter_hash_behavior(hash):
    """
    Check whether a file hash should be skipped based on sandbox analysis results.

    Args:
        hash -- File hash identifier.

    Returns:
        bool: True if the file should be skipped, False if it should be analyzed.
    """

    if filer_hash_alldata(hash):
        return True
    else:
        if hash not in sandboxes_types:
            return True  # Skip files that are not analyzed but any virustotal sandbox
        if sandboxes_types[hash] not in [
        "OS X Sandbox",
        "VirusTotal Box of Apples",
        "Zenbox macOS"
        ]:
            return True  # Skip files that are not analyzed but any virustotal sandbox
        else:
            print("to analyze -------------------------------")
            return False



