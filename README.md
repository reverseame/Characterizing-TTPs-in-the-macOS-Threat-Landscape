# Characterizing-TTPs-in-the-macOS-Threat-Landscape
Source data and Scripts used for the paper: Characterizing Tactics, Techniques, and Procedures in the macOS Threat Landscape

# Installation and Usage
The scripts runs with Python 3.11+. To use the scripts you only have to change the path where source data is and output data and run it.
# Scripts
die.py — Get entropy of each hash with D.I.E.  
checkdga.py — Check domains comparing domains to DGARCHIVE  
commonMethods.py — Some methods that are used by different scripts  
createGraphics.py — Parser of the majority of information from reports and generator of the majority of tables and figures  
filters.py — Functions to filter samples and analyze only executable binaries  
getFileTypeLanguageAndSymbols.py — Get file types, language and symbols information from radare
GetNeutrinoInfo.py — Get neutrino information of domains and IPs  
getVTNetwrokInfo.py — Get V.T. network information of domains and IPs classificating them as malicious or not  
mapperTechniquesToTactics.py -- Map techniques of MITRE to tactics of MITRE and convert the technique numbers to names  
radareComplementaryInfo.py -- Get information not getted before from radare; size, stripped, number of symbols, complexity, CPU type, and file type  
timelinecpuSamples.py — Timeline CPU and sandbox figures  


# Results
all_df_merged.csv -- Basic info from each hash, family, submission date, code signature information and cpu type  
radare_not_ios.csv -- info from radare: stripped, number of symbols, size, complexity, cputype, filetype  
countMalware_df.csv -- Sum of malware from different families  
Die.csv -- Entropy from die of each bianry  
Filetype.csv -- Filetype of each binary  
iOShashes.csv -- All the Mach-O hashes that are made for iOS  
mitre_df.csv -- Behavior of each binary  
sandbox_Df_filtered.csv -- Sandbox where the binary has been executed  
symbols_modified.csv -- All the symbols extracted with radare  
command_count.csv -- Commands used for all the binaries  
dynamicInfo.csv -- Linked status per binary  
file_opened_counts.csv -- All the files opened by the binaries during execution  
file_written_counts -- All the files written by the binaries during execution  
Langs.csv -- Programming language based on the analysis of radare  
lib_counts.csv -- Libraries included from all binaries  
unique_hashes_with_info.csv -- Binaries that have behavior in the V.T. sandboxes  
hash_and_malicious_ratio.csv -- Hash and his ratio of malicious detected by A.V. by V.T., the total is the sum of A.V. that has classified the different files by harmless, suspicious, undetected and malicious.

# Network info
basicNetwork.csv -- Network info of each binary  
dns_counts.csv -- All domains consulted  
ips_counts.csv -- All IPs consulted  
methods_count.csv -- All HTTP methods used  
content_type_count.csv -- All HTTP content type used  
malicious_domains.csv -- Domains classified as malicious by V.T.  
malicious_ips.csv -- IPs classified as malicious by V.T.  
Domains_Summary.log -- Summary information of all domains consulted to NeutrinoAPI  
Ips_Summary.log -- Summary information of all IPs consulted to NeutrinoAPI  

# Authors
Daniel Lastanao Miró, Project Leader  
Javier Carrillo-Mondéjar, Project Member  
Ricardo J. Rodríguez, Project Member  

# License
Licensed under the GNU [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) license.
