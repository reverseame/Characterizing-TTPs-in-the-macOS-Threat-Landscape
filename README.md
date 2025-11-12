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
The files that are missing it's due to VirusTotal’s data sharing policy, we are not allowed to redistribute the reports of the hashes and the proper information used for the analysis. 
radare_not_ios.csv -- info from radare: stripped, number of symbols, size, complexity, cputype, filetype  
Die.csv -- Entropy from die of each bianry  
iOShashes.csv -- All the Mach-O hashes that are made for iOS  
Langs.csv -- Programming language based on the analysis of radare  
hash_and_malicious_ratio.csv -- Hash and his ratio of malicious detected by A.V. by V.T., the total is the sum of A.V. that has classified the different files by harmless, suspicious, undetected and malicious.

# Authors
Daniel Lastanao Miró  
Javier Carrillo-Mondéjar  
Ricardo J. Rodríguez

# Fundings
This research was supported in part by grant PID2023-151467OA-I00 (CRAPER), funded by MICIU/AEI/10.13039/501100011033 and by ERDF/EU, by grant TED2021-131115A-I00 (MIMFA), funded by MICIU/AEI/10.13039/501100011033 and by the European Union NextGenerationEU/PRTR, by grant Proyecto Estratégico Ciberseguridad EINA UNIZAR, funded by the Spanish National Cybersecurity Institute (INCIBE) and the European Union NextGenerationEU/PRTR, by grant Programa de Proyectos Estratégicos de Grupos de Investigación (DisCo, ref. T21-23R), funded by the University, Industry and Innovation Department of the Aragonese Government. We thank the VT team for granting academic research access to their services.

# License
Licensed under the GNU [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) license.
