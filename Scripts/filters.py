import pandas as pd

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
    if hash not in file_types or file_types[hash] != "application/x-mach-binary":
        return True  # Skip files that do not match the 'application/x-mach-binary' type

    if hash not in header_file_type or header_file_type[hash] != "Executable file":
        return True  # Skip files that do not match the 'EXECUTABLE' type in the header

    if hash in ios_hashes_df[columnNameHash].values:
        return True
    
    return False

def filter_hash_behavior(hash):

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



