import filters
import subprocess
import pandas as pd
from pathlib import Path
import json
import requests
import time 
import os
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import datetime
import sys
from collections import defaultdict
import plotly.express as px
import ast  # To convert the string list into a list
from matplotlib import rc
from decimal import Decimal, ROUND_HALF_UP
import re
import mapperTechniquesToTactics #File
import commonMethods #File
import VT_download_normal_report_and_behavior #File
import getInfoRadare #File

__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"

rc('font', family='serif', serif='Times New Roman', size=22)
plt.rcParams['text.usetex'] = False


outputFolder = "../Output"
outputCSVFolder =  "../Output/csv"
outputCSVFolderSource =  "../Output/csv/src"
outputTxtFamily = "../Output/Hashes_info/familyOfEachMalware.txt"
output_dir = '../Output/Hashes_info/VT_JSON'
output_dir_behaviour_summary = '../Output/Hashes_info/VT_MBCS_JSON'
config_file = 'config.ini'
save_path = '../Output/Graphics/'
columnNameFirstSubmissionDate = "first_submission_date" 
columnNameHash = "Hash"
columnNameFamily = "Family"
columnNameTechnique = "Technique"
columnNameCount = "Count"
columnNameLastSubmissionDate = "last_submission_date"
columnNameTactic = "Tactic"
columnNameMalwareFamily = "Malware_Family"
columnNameCpu = "cpu_type"
columnNamePercentage = "% Over total"
columnNamePacked = "Packed"
MITRE_ATTACK_DATA = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json').json()
TECHNIQUES = {technique['external_references'][0]['external_id']:technique['name'] for technique in MITRE_ATTACK_DATA['objects'] if technique['type'] == 'attack-pattern' and not technique.get('revoked')}



def generate_mitre_navigator_layout(mitre_df):
    """
    Generate a MITRE ATT&CK Navigator JSON layer from a dataframe of techniques per malware family.

    Args:
        mitre_df -- DataFrame containing columns [Family, Technique] at minimum.
    """
    modified_df = mitre_df.drop_duplicates(subset=[columnNameFamily,columnNameTechnique]) #Get all the techniques per family that are used
    num_unique_families = modified_df[columnNameFamily].nunique()
    techniques = modified_df[columnNameTechnique].value_counts().to_dict()
    output_file = "../Output/combined_navigator_layout.json"
    # Define the base template for the Navigator layer
    navigator_layout = {
        "name": "Combined ATT&CK Techniques",
        "versions": {
            "attack": "15",
            "navigator": "5.0.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Combined ATT&CK techniques used by various malware families",
        "filters": {
            "platforms": ["macOS"]  
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "none"
        },
        "hideDisabled": False,
        "techniques": [],
            "gradient": {
                "colors": [
                    "#8ec843ff",
                    "#ffe766ff",
                    "#ff6666ff"
                ],
            "minValue": 0,
            "maxValue": num_unique_families
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False
    }

    for technique, count in techniques.items():
        tactics = mapperTechniquesToTactics.technique_to_tactic.get(technique, [])
        if not tactics:
            continue
        for tactic in tactics:
            navigator_layout["techniques"].append({
                "techniqueID": technique,
                "tactic": tactic,
                "color": "",
                "comment": f"Observed {count} times across malware families",
                "enabled": True,
                "metadata": [],
                "showSubtechniques": False,
                "score": count
            })
    with open(output_file, 'w') as f:
        json.dump(navigator_layout, f, indent=4)



def parseMalwareAndFamily(outputTxtFamily):
    """
    Parse a text file mapping malware hashes to families into a dataframe.

    Args:
        outputTxtFamily -- Path to the family mapping text file.

    Returns:
        pd.DataFrame: DataFrame with columns [Hash, Malware_Family].
    """
    first_line = f"{columnNameHash},{columnNameMalwareFamily}"
    file_data = None
    with open(outputTxtFamily,'r+') as file:
        file_data = file.read()
        file.seek(0,0)
        file.write(first_line + '\n' + file_data)
    
    with open(outputTxtFamily,'r') as file:
        file_data = file.read()

    file_data = file_data.replace('	',',')

    with open(outputTxtFamily,'w') as file:
        file.write(file_data)

    malware_df = pd.read_csv(outputTxtFamily)    
    return malware_df

def get_technique(tid): 
    """
    Resolve a MITRE ATT&CK technique ID to its human-readable name.

    Args:
        tid -- Technique ID.

    Returns:
        str | None -- Technique name if found, otherwise None.
    """
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    else:
        return None 


#To use this function you need to pip install avclass-malicialab 
def passJSONToAvclass(output_dir,outputTxtFamily):
    """
    Run AVClass on VirusTotal JSON reports to label samples by malware family.

    Args:
        output_dir -- Directory with VT JSON files.
        outputTxtFamily -- Output file path for AVClass results.
    """

    cmdCommand = f"avclass -d {output_dir} -o {outputTxtFamily}"   
    process = subprocess.Popen(cmdCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

def getMalwareFamily(malware_df,hash):
    """
    Retrieve the malware family associated with a specific hash.

    Args:
        malware_df -- DataFrame containing [Hash, Malware_Family].
        hash -- Malware hash to look up.

    Returns:
        str -- Malware family name (prefix before ':' if present).
    """

    family = malware_df.loc[malware_df[columnNameHash] == hash, columnNameMalwareFamily].values[0] 
    family = family.split(':')[0]
    return family


def addHashAndTechniqueRow(hash,malware_family,techniqueName,mitre_df,date):
    """
    Add a new row (hash, family, technique, count, date) to a MITRE dataframe if not already present.

    Args:
        hash -- Malware hash.
        malware_family -- Malware family name.
        techniqueName -- Technique object containing 'id'.
        mitre_df -- Existing MITRE dataframe.
        date -- Submission date.

    Returns:
        pd.DataFrame -- Updated MITRE dataframe.
    """
    techniqueName = techniqueName['id']
    mask = (mitre_df[columnNameHash] == hash) & (mitre_df[columnNameFamily] == malware_family) & (mitre_df[columnNameTechnique] == techniqueName)
    if mitre_df.loc[mask].empty:
        mitre_df = pd.concat([pd.DataFrame([[hash,malware_family, techniqueName,1,date]], columns=[columnNameHash,columnNameFamily, columnNameTechnique,columnNameCount,columnNameFirstSubmissionDate]), mitre_df], ignore_index=True)
    return mitre_df

def addHashToAll(hash,malware_family,all_df,date):
    """
    Add a new row (hash, family, date) to the global dataframe of all samples.

    Args:
        hash -- Malware hash.
        malware_family -- Family name.
        all_df -- DataFrame of all samples.
        date -- Submission date.

    Returns:
        pd.DataFrame -- Updated DataFrame with the new entry.
    """
    all_df = pd.concat([pd.DataFrame([[hash,malware_family, date]], columns=[columnNameHash,columnNameFamily, columnNameFirstSubmissionDate]), all_df], ignore_index=True)
    return all_df

def countFamilyMalwareWithData(malware_family,countMalware_df):
    """
    Increment or initialize the count of samples for a malware family.

    Args:
        malware_family -- Family name to update.
        countMalware_df -- DataFrame with [Family, Count].

    Returns:
        pd.DataFrame -- Updated count dataframe.
    """
    mask = (countMalware_df[columnNameFamily] == malware_family) 
    try: 
        count = countMalware_df.loc[mask, columnNameCount].values[0]
        countMalware_df.loc[mask, columnNameCount] = int(count) + 1
    except:
        countMalware_df = pd.concat([pd.DataFrame([[malware_family, 1]], columns=[columnNameFamily, columnNameCount]), countMalware_df], ignore_index=True)
    
    return countMalware_df


def getFirstSubmissionDateOfHash(hash,path_normal_report):
    """
    Extract the first submission date of a sample from its VirusTotal report.

    Args:
        hash -- Malware hash.
        path_normal_report --  Directory containing VT JSON reports.

    Returns:
        str -- First submission date formatted as "YYYY-MM-DD".
    """
    path = path_normal_report + "/" + hash
    with open(path) as f:
        data = json.load(f)
        first_submission_date = datetime.datetime.fromtimestamp( data['data']['attributes']['first_submission_date']).strftime('%Y-%m-%d')
        with open('../Output/csv/dates.csv', "a") as file:
            file.write(f'{hash},{first_submission_date}\n')
        return first_submission_date

def comparationBetweenAllFamiliesAndBehavior(countMalware_Behavior_df,all_df):
    """
    Compare malware families with and without behavioral data. And creates a csv file with the result

    Args:
        countMalware_Behavior_df -- Families with behavior sample counts.
        all_df -- DataFrame of all samples per family.
    """
    all_df = all_df.groupby([columnNameFamily])[columnNameFamily].size().reset_index(name=columnNameCount)
    columnNameFraction = "Behavior/Total"
    columnNameResult = "Coefficient"
    all_df[columnNameFraction] = None
    all_df[columnNameResult] = None
    
    for index, row in countMalware_Behavior_df.iterrows():
        family = row[columnNameFamily]
        count_behavior = row[columnNameCount]
        mask = (all_df[columnNameFamily] == family) 
        try: 
            count_all = all_df.loc[mask, columnNameCount].values[0]
            all_df.loc[mask, columnNameFraction] = str(count_behavior) + "/" + str(count_all)
            all_df.loc[mask, columnNameResult] =  count_behavior/count_all
        except:
            pass #Family missing

    all_df[columnNameResult] = all_df[columnNameResult].fillna(0)
    all_df = all_df.sort_values(by=[columnNameCount],ascending=False)
    all_df.to_csv('../Output/csv/comparationBetweenAllFamiliesAndBehavior.csv',index=False)

def familiesWithoutBehavior(countMalware_Behavior_df, all_df):
    """
    Identify families with missing behavior reports and compute differences. And creates a csv with the result.

    Args:
        countMalware_Behavior_df -- Families with behavior sample counts.
        all_df -- DataFrame of all samples per family.
    """
    all_df = all_df.groupby([columnNameFamily])[columnNameFamily].size().reset_index(name=columnNameCount)
    
    columnNameFraction = "Behavior/Total"
    columnNameResult = "Coefficient"
    columnNameMissingBehavior = "No_Behavior_Count"
    
    all_df[columnNameFraction] = None
    all_df[columnNameResult] = None
    all_df[columnNameMissingBehavior] = None  

    for index, row in countMalware_Behavior_df.iterrows():
        family = row[columnNameFamily]
        count_behavior = row[columnNameCount]
        mask = (all_df[columnNameFamily] == family)
        
        try:
            count_all = all_df.loc[mask, columnNameCount].values[0]
            all_df.loc[mask, columnNameFraction] = f"{count_behavior}/{count_all}"
            all_df.loc[mask, columnNameResult] = count_behavior / count_all
            all_df.loc[mask, columnNameMissingBehavior] = count_all - count_behavior
        except:
            pass  # Family missing

    # Fill missing values in columns
    all_df[columnNameResult] = all_df[columnNameResult].fillna(0)
    all_df[columnNameMissingBehavior] = all_df[columnNameMissingBehavior].fillna(all_df[columnNameCount])

    all_df = all_df.sort_values(by=[columnNameMissingBehavior], ascending=False)
    all_df.to_csv('../Output/csv/familiesWithoutBehavior.csv', index=False)



def topTTPUsed(mitre_df,total_bianries_withmitre_info):
    """
    Compute and export the most used MITRE ATT&CK techniques in a csv file.

    Args:
        mitre_df -- DataFrame containing technique usage.
        total_bianries_withmitre_info -- Total number of analyzed samples.

    """
    modified_mitre_df = mitre_df.copy()
    
    df_val_counts = modified_mitre_df.value_counts(columnNameTechnique)
    df_value_counts_reset = df_val_counts.reset_index() 
    df_value_counts_reset.columns = [columnNameTechnique, 'Count'] 
    df_value_counts_reset["Tactic"] = df_value_counts_reset[columnNameTechnique].map( lambda x: mapperTechniquesToTactics.get_technique_to_tactic().get(x, [])) 
    df_value_counts_reset[columnNameTechnique] = df_value_counts_reset[columnNameTechnique].apply(get_technique)
    df_value_counts_reset = df_value_counts_reset.dropna(subset=[columnNameTechnique])
    df_value_counts_reset[columnNamePercentage] = (df_value_counts_reset["Count"].astype(float) /int(total_bianries_withmitre_info))*100
    print("executed")
    df_value_counts_reset[columnNamePercentage] = df_value_counts_reset[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")

    df_value_counts_reset.to_csv('../Output/csv/topTTPUsed.csv', index=False)

def split_tactics(row):
    """
    Expand a row with multiple tactics into separate rows (1 tactic per row).

    Args:
        row -- Row containing a 'Tactic' string/list.

    Returns:
        pd.DataFrame -- Expanded dataframe with repeated values per tactic.
    """
    tactic_str = row[columnNameTactic]
    tactics_list = [n.strip() for n in tactic_str]
    # Create a new DataFrame for each tactic, repeating the other columns for each tactic
    expanded_rows = pd.DataFrame({
        **{col: [row[col]] * len(tactics_list) for col in row.index},  # Repeat all original columns
        'Tactic': tactics_list  # Replace the Tactic column with the individual tactics
    })
    return expanded_rows


def tactic_distribution(mitre_df,total_bianries_withmitre_info):
    """
    Generate tactic distribution from MITRE DataFrame and save to CSV.

    Args:
        mitre_df -- DataFrame containing technique and hash info.
        total_samples -- Total number of binaries with MITRE info.
    """
    modified_mitre_df = mitre_df.copy()
    modified_mitre_df[columnNameTactic] = modified_mitre_df[columnNameTechnique].map( lambda x: mapperTechniquesToTactics.get_technique_to_tactic().get(x, [])) 

    df_expanded = pd.concat([split_tactics(row) for _, row in modified_mitre_df.iterrows()], ignore_index=True)
    df_expanded = df_expanded.drop_duplicates(subset=[columnNameHash,columnNameTactic])
    df_expanded = df_expanded.value_counts(columnNameTactic)
    df_expanded = df_expanded.reset_index()
    df_expanded.columns = [columnNameTactic, columnNameCount] 
    dfCountAndSave(df_expanded,columnNameTactic,int(total_bianries_withmitre_info) ,'../Output/csv/tactic_disctribution.csv')

def create_gantt_chart_by_tactic():
    """
    Create Gantt chart of techniques grouped by tactic, saved as PDF.
    """
    ttps_time_df = pd.read_csv('../Output/csv/ttps_time.csv')
    
    ttps_time_df[columnNameFirstSubmissionDate] = pd.to_datetime(ttps_time_df[columnNameFirstSubmissionDate])
    ttps_time_df[columnNameLastSubmissionDate] = ttps_time_df[columnNameLastSubmissionDate].fillna(ttps_time_df[columnNameFirstSubmissionDate])
    ttps_time_df[columnNameLastSubmissionDate] = pd.to_datetime(ttps_time_df[columnNameLastSubmissionDate])
    
    # Extract only the first tactic from the list for each entry
    ttps_time_df[columnNameTactic] = ttps_time_df[columnNameTactic].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)
    ttps_time_df['Tactic'] = ttps_time_df[columnNameTactic].apply(lambda x: x[0] if isinstance(x, list) and len(x) > 0 else None)
    ttps_time_df['Task'] = ttps_time_df[columnNameTechnique]
    ttps_time_df['Start'] = ttps_time_df[columnNameFirstSubmissionDate]
    ttps_time_df['Finish'] = ttps_time_df.apply(
        lambda row: row[columnNameLastSubmissionDate] if row[columnNameFirstSubmissionDate] != row[columnNameLastSubmissionDate] 
        else row[columnNameFirstSubmissionDate] + pd.Timedelta(hours=336), axis=1
    )

    # Define colors for unique tactics
    unique_tactics = ttps_time_df['Tactic'].unique()
    colors_list = ['orange', 'lime', 'cyan', 'yellow', 'lightgreen', 'deepskyblue', 'gold', 'lightcoral', 'lightpink', 'green']
    colors_dict = {tactic: colors_list[i % len(colors_list)] for i, tactic in enumerate(unique_tactics)}

    fig = px.timeline(ttps_time_df, x_start='Start', x_end='Finish', y='Task', color='Tactic',
                      color_discrete_map=colors_dict)

    fig.update_layout(
    width=1600,
    height=900,
    xaxis_title='Date',
    yaxis_title='',
    showlegend=True,
    margin=dict(l=40, r=40, t=40, b=60),
    font=dict(size=10),
    legend=dict(
        x=0.01,    
        y=0.01,     
        xanchor="left",
        yanchor="bottom"
    )
)
    
    fig.update_yaxes(showticklabels=False)

    fig.update_xaxes(
        range=[ttps_time_df['Start'].min(), ttps_time_df['Finish'].max()],
        tickangle=45,
        dtick="M6",
        tickformat="%Y-%m",  
    )

    fig.add_shape(
        type='line',
        x0=ttps_time_df['Start'].min(),
        x1=ttps_time_df['Finish'].max(),
        y0=-2,
        y1=-2,
        line=dict(color='Black', width=2)
    )


    # Add annotations: inside if the bar is long, outside if short
    for index, row in ttps_time_df.iterrows():
        first_submission_date = row[columnNameFirstSubmissionDate]
        last_submission_date = row[columnNameLastSubmissionDate]
        # Calculate the duration of the bar
        bar_duration = last_submission_date - first_submission_date

        if bar_duration < pd.Timedelta(days=2*365):  # Place text outside for short bars (< 2 years)
            fig.add_annotation(
                x=row['Start'] - pd.Timedelta(days=60),  # Position just outside the bar
                y=row['Task'],
                text=row['Task'], 
                showarrow=False,
                xanchor="right",
                font=dict(size=10, color='black'),
                align="right"
            )
        else:  # Place text inside for longer bars (>= 2 years)
            fig.add_annotation(
                x=row['Start'] + pd.Timedelta(days=10),  # Position slightly inside the bar
                y=row['Task'],
                text=row['Task'],
                showarrow=False,
                xanchor="left",
                font=dict(size=10, color='black'),
                align="right"
            )

    fig.write_image(os.path.join(save_path, "gantt_chart_by_tactic.pdf"), format='pdf', width=1600, height=900, scale=2)

def percentagesOverTheYears():
    """
    Calculate the percentage distribution of samples per year with the help of all_df_merged.csv and creates a file with the result.
    """
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    all_df = deleteIOSRows(all_df)

    all_df['first_submission_date'] = pd.to_datetime(all_df['first_submission_date'])

    all_df['Year'] = all_df['first_submission_date'].dt.year

    total_samples = len(all_df)

    samples_per_year = all_df['Year'].value_counts().sort_index()

    percentage_per_year = (samples_per_year / total_samples) * 100

    percentage_df = percentage_per_year.reset_index()
    percentage_df.columns = ['Year', 'Percentage']

    percentage_df.to_csv("../Output/csv/percentage_Of_Samples_Each_year.csv", index=False)

def getInfoRadareFunction():
    """
    Perform exploratory analysis on Radare output and creates two different files with information from Radare2.
    """

    radare_df = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    print(len(radare_df))
    radare_df = radare_df[~radare_df[columnNameHash].apply(filters.filer_hash_alldata)]
    print(len(radare_df))
    stripped_count = radare_df['Stripped'].value_counts(dropna=False)
    radare_df['Size'] = pd.to_numeric(radare_df['Size'], errors='coerce')

    # Calculate the minimum, average, and maximum file size
    min_size = radare_df['Size'].min()
    avg_size = radare_df['Size'].mean()
    max_size = radare_df['Size'].max()

    min_symbols = radare_df['N_Symbols'].min()
    avg_symbols = radare_df['N_Symbols'].mean()
    max_symbols = radare_df['N_Symbols'].max()

    # Create a DataFrame with both Size and N_Symbols statistics
    stats_df = pd.DataFrame({
        'Min_Size': [min_size],
        'Avg_Size': [avg_size],
        'Max_Size': [max_size],
        'Min_N_Symbols': [min_symbols],
        'Avg_N_Symbols': [avg_symbols],
        'Max_N_Symbols': [max_symbols]
    })

    # Save the statistics table to CSV
    stats_df.to_csv('../Output/csv/file_size_and_symbols_statistics.csv', index=False)



    # Save the result to a new file
    with open('../Output/csv/stripped_counts.csv', 'w') as f:
        f.write("Stripped,Count\n")
        f.write(f"True,{stripped_count.get(True, 0)}\n")
        f.write(f"False,{stripped_count.get(False, 0)}\n")
        f.write(f"Empty,{stripped_count.get(float('nan'), 0)}\n")

def packed_count():
    """
    Count packed vs non-packed samples and calculate percentages.
    """
    die_df = pd.read_csv('../Output/csv/src/die.csv')
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    die_df = die_df[~die_df[columnNameHash].apply(filters.filer_hash_alldata)]
    all_df = all_df[~all_df[columnNameHash].apply(filters.filer_hash_alldata)]
    
    hashes_in_all_df = all_df[columnNameHash].unique()  
    die_df = die_df[die_df[columnNameHash].isin(hashes_in_all_df)] 
    df_val_counts = die_df.value_counts(columnNamePacked)
    df_value_counts_reset = df_val_counts.reset_index() 
    df_value_counts_reset.columns = [columnNamePacked, 'Count'] 
    df_value_counts_reset[columnNamePercentage] = (df_value_counts_reset["Count"].astype(float) /int(df_value_counts_reset['Count'].sum()))*100
    df_value_counts_reset[columnNamePercentage] = df_value_counts_reset[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")
    df_value_counts_reset.to_csv('../Output/csv/packed_count.csv', index=False)


def makeTableCPUComparation():
    """
    Build a comparative table of CPU samples by packing, stripping, and behavior status. Saves the result in a csv file
    """
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    stripped_df = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    stripped_df = stripped_df[~stripped_df[columnNameHash].apply(filters.filer_hash_alldata)]
    packed_df = pd.read_csv('../Output/csv/src/die.csv')
    packed_df = packed_df[~packed_df[columnNameHash].apply(filters.filer_hash_alldata)]
    behavior_df = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')
    all_df = all_df[~all_df[columnNameHash].apply(filters.filer_hash_alldata)]
    # Data cleaning and conversion
    all_df = all_df.dropna(subset=[columnNameCpu])
    all_df[columnNameCpu] = all_df[columnNameCpu].astype(str).str.strip()
    all_df = all_df[all_df[columnNameCpu] != ""]


    # Clean up packed_df and stripped_df
    packed_df = packed_df[[columnNameHash, columnNamePacked]].drop_duplicates()
    stripped_df = stripped_df[[columnNameHash, 'Stripped']].drop_duplicates()
    
    
    packed_df['Packed'] = packed_df['Packed'].map({'packed': True, 'not packed': False}) # Convert Packed column to boolean values if necessary
    stripped_df = stripped_df.dropna(subset=['Stripped'])
    print("Unique values in 'Stripped' before mapping:", stripped_df['Stripped'].unique())

    
    stripped_df['Stripped'] = stripped_df['Stripped'].replace({'True': True, 'False': False}) # Convert Stripped column to boolean values if necessary
    stripped_df['Stripped'] = stripped_df['Stripped'].astype(bool)

    
    all_df = pd.merge(all_df, packed_df, on=columnNameHash, how='left') # Merge the 'packed' column into all_df based on 'columnHash'
    all_df = pd.merge(all_df, stripped_df, on=columnNameHash, how='left') # Merge the 'stripped' column into all_df based on 'columnHash'

    all_df['HasBehavior'] = all_df[columnNameHash].isin(behavior_df[columnNameHash])

    print(len(all_df))
    print(all_df.head())

    summary_df = all_df.groupby(columnNameCpu).agg(
        total_count=(columnNameHash, 'size'),                        # Total number of samples for each CPU type
        total_packed=('Packed', lambda x: x.dropna().sum()),       # Count of packed samples (True values, excluding NaNs)
        total_not_packed=('Packed', lambda x: (x == False).sum()), # Count of not packed samples (False values, excluding NaNs)
        total_stripped=('Stripped', lambda x: x.dropna().sum()),     # Count of stripped samples (True values, excluding NaNs)
        total_not_stripped=('Stripped', lambda x: (x == False).sum()), # Count of not stripped samples (False values, excluding NaNs)
        total_behavior=('HasBehavior', 'sum'),                     # Count of samples with behavior (True values)
        total_no_behavior=('HasBehavior', lambda x: (~x).sum())    # Count of samples without behavior (False values)
    ).reset_index()

    summary_df = summary_df.sort_values(by='total_count', ascending=False)
    summary_df.to_csv('../Output/csv/cpu_comparation_packed_stripped.csv', index=False)    


def dfCountAndSave(dictordf,columnNameItem,total_items,pathToSave):
    """
    Convert a dictionary or DataFrame of counts into a percentage table and save to CSV.

    Args:
        dictordf -- Input data.
        columnNameItem -- Name of the item/category column.
        total_items -- Total number of samples for percentage calculation.
        pathToSave -- Output CSV path.

    """
    if isinstance(dictordf, dict): #The object is a dictionary so convert to DF
        dict_df = pd.DataFrame(list(dictordf.items()), columns=[columnNameItem, columnNameCount])
    else:
        dict_df = dictordf

    dict_df[columnNamePercentage] = (dict_df[columnNameCount].astype(float) / total_items ) * 100
    dict_df[columnNamePercentage] = dict_df[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")
    dict_df = dict_df.sort_values(by=columnNameCount, ascending=False)
    dict_df.to_csv(pathToSave, index=False)




def create_graphics_malware_behaviors(path,malware_df,path_normal_report,update):
    """
    Generate behavioral analysis and visualizations for malware samples.

    Args:
        path -- Directory containing JSON behavior reports.
        malware_df -- DataFrame with malware family metadata.
        path_normal_report -- Path to normal report data (for dates).
        update -- If 1, parse and update datasets from scratch; 
                      if 0, load preprocessed CSV files.
    """
    path = Path(path)
    total_items = sum(1 for entry in path.rglob('*'))
    command_counts = defaultdict(int)
    files_opened_counts = defaultdict(int)
    files_written_counts = defaultdict(int)
    
    with open('../Output/csv/dates.csv', "w") as file:
            file.write(f'Hash,first_submission_date\n')
    if update == 1:
        all_df = pd.DataFrame(columns=[columnNameHash,columnNameFamily,columnNameFirstSubmissionDate])
        mitre_df = pd.DataFrame(columns=[columnNameHash,columnNameFamily, columnNameTechnique,columnNameCount,columnNameFirstSubmissionDate])
        countMalware_df = pd.DataFrame(columns=[columnNameFamily,columnNameCount])
        start_time = time.time()
        total_bianries_withmitre_info = 0
        total_bianries_withcommands_info = 0
        total_binaries_withfiles_opened = 0
        total_binaries_withfiles_written = 0

        hashes_with_mitre_info = set()
        hashes_with_commands_info = set()
        hashes_with_files_opened = set()
        hashes_with_files_written = set()


        for i, entry in enumerate(path.rglob('*')):
            commonMethods.custom_progress_bar("Progress getInfoAboutEachBinary behavior, " ,i + 1, total_items,start_time)
            file_hash = entry.stem
            date = getFirstSubmissionDateOfHash(entry.stem,path_normal_report)
            
            print("\n" + file_hash + "\n")
            if filters.filter_hash_behavior(file_hash): #if a hash not pass our filters we dont want it in the chart
                continue
            print("analyzing :", file_hash)

            
            malware_family = getMalwareFamily(malware_df,entry.stem)
            
            all_df = addHashToAll(entry.stem,malware_family,all_df,date)
            with open(entry) as f:
                data = json.load(f)
                try:
                    command_executions = data['data'].get('command_executions', [])
                    total_bianries_withcommands_info+= 1
                    hashes_with_commands_info.add(entry.stem)
                    commands_already_executed = []
                    # Process each command and extract only the first word (the actual command), and if its sh the command i get the first three words to see the use of that command, and i split by && to get also the commands that are used in one line
                    for command in command_executions:
                        first_word = command.split(' ')[0]  # Split by space and get the first word
                        if first_word not in commands_already_executed:
                            if not first_word == "sh":
                                commands_already_executed.append(first_word)
                                command_counts[first_word] += 1  
                            else:
                                if '&&' in command:
                                    command_blocks = command.split('&&')  # Split by '&&' if present
                                else:
                                    command_blocks = [command]  # Treat as one block if no '&&'
                                for block in command_blocks: # Idk if do this bc count other commands one linner
                                    first_word = block.strip().split()[0]
                                    if first_word not in commands_already_executed:
                                        commands_already_executed.append(first_word)
                                        command_counts[first_word] += 1  

                                first_three_words = ' '.join(command.split(' ')[:3])
                                commands_already_executed.append(first_three_words)
                                command_counts[first_three_words] += 1  
                except:
                    pass # sample with no command_executions


                try:
                    files_opened = data['data'].get('files_opened', [])
                    countMalware_df = countFamilyMalwareWithData(malware_family,countMalware_df)
                    total_binaries_withfiles_opened+=1
                    hashes_with_files_opened.add(entry.stem)
                    for file in files_opened:
                        if "Library" not in file:
                            files_opened_counts[file] += 1  # Count every occurrence of the first word
                except:
                    pass # sample with no files_opened
                try:
                    files_written = data['data'].get('files_written', [])
                    total_binaries_withfiles_written+=1
                    hashes_with_files_written.add(entry.stem)
                    for file in files_written:
                        files_written_counts[file] += 1  # Count every occurrence of the first word
                except:
                    pass #sample with no files_opened

                if "data" in data and data["data"] is not None and "mitre_attack_techniques" in data["data"]: # Add columns refering to mitre_attack_techniques
                    
                    hashes_with_mitre_info.add(entry.stem)
                    total_bianries_withmitre_info += 1
                    for technique in data["data"]['mitre_attack_techniques']:
                        mitre_df = addHashAndTechniqueRow(entry.stem,malware_family,technique,mitre_df,date)

        dfCountAndSave(command_counts,'Command',total_bianries_withcommands_info,'../Output/csv/command_counts.csv')
        dfCountAndSave(files_opened_counts,'File',total_binaries_withfiles_opened,'../Output/csv/files_opened_counts.csv')
        dfCountAndSave(files_written_counts,'File',total_binaries_withfiles_written,'../Output/csv/files_written_counts.csv')




        mitre_info_df = pd.DataFrame(list(hashes_with_mitre_info), columns=[columnNameHash])
        mitre_info_df.to_csv('../Output/csv/mitre_info_hashes.csv', index=False)

        commands_info_df = pd.DataFrame(list(hashes_with_commands_info), columns=[columnNameHash])
        commands_info_df.to_csv('../Output/csv/commands_info_hashes.csv', index=False)

        files_opened_info_df = pd.DataFrame(list(hashes_with_files_opened), columns=[columnNameHash])
        files_opened_info_df.to_csv('../Output/csv/files_opened_info_hashes.csv', index=False)

        files_written_info_df = pd.DataFrame(list(hashes_with_files_written), columns=[columnNameHash])
        files_written_info_df.to_csv('../Output/csv/files_written_info_hashes.csv', index=False)

        all_hashes_with_info = hashes_with_mitre_info.union(hashes_with_mitre_info,hashes_with_commands_info, hashes_with_files_opened, hashes_with_files_written)

        with open('../Output/csv/unique_hashes_with_info.csv', "w") as file:
            file.write(f"Hash\n")
            for file_hash in all_hashes_with_info:
                file.write(f"{file_hash}\n")
        with open('../Output/csv/totals.csv', "a") as file:
            file.write(f'total_bianries_withmitre_info: {total_bianries_withmitre_info}\n')
            file.write(f'total_bianries_withcommands_info: {total_bianries_withcommands_info}\n')
            file.write(f'total_binaries_withfiles_opened: {total_binaries_withfiles_opened}\n')
            file.write(f'total_binaries_withfiles_written: {total_binaries_withfiles_written}\n')


        mitre_df.to_csv('../Output/csv/src/mitre_df.csv', index=False)
        countMalware_df.to_csv('../Output/csv/src/countMalware_df.csv', index=False)
    else:
        all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
        mitre_df = pd.read_csv('../Output/csv/src/mitre_df.csv')
        countMalware_df = pd.read_csv('../Output/csv/src/countMalware_df.csv')
        all_hashes_with_info = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')


    mitre_df = deleteIOSRows(mitre_df)

    packed_count()

    #Create graphics
    total_bianries_withmitre_info = mitre_df[columnNameHash].nunique()
    
    topTTPUsed(mitre_df,total_bianries_withmitre_info)
    tactic_distribution(mitre_df,total_bianries_withmitre_info)
    create_gantt_chart_by_tactic() 

    
    
    comparationBetweenAllFamiliesAndBehavior(countMalware_df,all_df)
    familiesWithoutBehavior(countMalware_df, all_df)
    generate_mitre_navigator_layout(mitre_df)



def normalize_cpu_type(cpu_type):
    """
    Normalize raw CPU type strings to consistent labels.

    Args:
        cpu_type -- Raw CPU type string (possibly containing duplicates, 
                        inconsistent order, or extra quotes).

    Returns:
        str -- Normalized CPU type string based on predefined mappings. 
             If no mapping is found, returns the stripped input string.
    """
    cpu_type = cpu_type.strip('"')
    normalization_map = {
        'x86 64-bit, ARM 64-bit': 'ARM 64-bit, x86 64-bit',
        'ARM 64-bit, x86 64-bit': 'ARM 64-bit, x86 64-bit',  
        'x86 64-bit, x86': 'x86 64-bit',  
        'x86, x86 64-bit': 'x86 64-bit',
        'ARM 64-bit, ARM 64-bit': 'ARM 64-bit',
        'x86 64-bit, x86, PowerPC': 'x86 64-bit, PowerPC',
        'x86, x86 64-bit, PowerPC': 'x86 64-bit, PowerPC',
        'ARM, ARM': 'ARM',
        'ARM, ARM, ARM 64-bit': 'ARM, ARM 64-bit',
        'PowerPC, x86, x86 64-bit': 'x86 64-bit, PowerPC',
        'x86, x86 64-bit, PowerPC, PowerPC 64-bit': 'x86 64-bit, PowerPC',
        'PowerPC, x86 64-bit, x86': 'x86 64-bit, PowerPC', 
        'ARM, ARM, ARM 64-bit, ARM 64-bit': 'ARM, ARM 64-bit',   
        'ARM, ARM 64-bit, ARM 64-bit': 'ARM, ARM 64-bit',   
        'x86, PowerPC, x86 64-bit, PowerPC 64-bit': 'x86 64-bit, PowerPC,PowerPC 64-bit',
        'ARM 64-bit, ARM 64-bit, ARM 64-bit' : 'ARM 64-bit',   

        'ARM 64-bit, x86 64-bit' : 'ARM 64-bit, x86 64-bit',   
        'PowerPC, x86' : 'x86 64-bit, PowerPC',
        'x86' : 'x86 64-bit',
        'x86, PowerPC'  : 'x86 64-bit, PowerPC',
        'ARM, ARM 64-bit' : 'ARM, ARM 64-bit',   
        'x86, PowerPC,PowerPC 64-bit' : 'x86 64-bit, PowerPC,PowerPC 64-bit',
        'NS32332 64-bit, x86': 'NS32332 64-bit, x86 64-bit',
    }
    return normalization_map.get(cpu_type.strip(), cpu_type.strip())


def deleteIOSRows(df):
    """
    Remove iOS sample rows from a DataFrame.

    Args:
        df -- Input DataFrame containing malware samples 
                           with a hash column.

    Returns:
        pd.DataFrame -- Filtered DataFrame with all rows corresponding to 
                      iOS hashes removed.

    """
    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')
    df = df[~df[columnNameHash].isin(ios_hashes_df[columnNameHash])]
    return df



def create_graphics_malware_normal_report(output_dir,update):
    """
    Generate normal report analysis and visualizations for malware samples.

    Args:
        output_dir -- Directory containing JSON reports of binaries.
        update -- If 1, parse JSON reports and update datasets; 
                    if 0, reuse existing processed CSVs.
    """
    path = Path(output_dir)
    total_items = sum(1 for entry in path.rglob('*'))
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    lib_counts = defaultdict(int)

    
    if update == 1:
        all_df['code_sign'] = None
        start_time = time.time()
        for i, entry in enumerate(path.rglob('*')):
            commonMethods.custom_progress_bar("Progress getInfoAboutEachBinary normal, " ,i + 1, total_items,start_time)

            file_hash = entry.stem

            if filters.filer_hash_alldata(file_hash):
                continue
            with open(entry) as f:
                data = json.load(f)
                try:
                    stack = [data]
                    cpu_type = ""
                    while stack:
                        current = stack.pop()
                        if isinstance(current, dict):
                            if 'CPUType' in current:
                                cpu_type =  current['CPUType']
                            stack.extend(current.values())
                        elif isinstance(current, list):
                            stack.extend(current)
                    
                    
                    normalized_cpu_type = normalize_cpu_type(cpu_type)
                    normalized_cpu_type = normalized_cpu_type.strip('"')
                    all_df.loc[all_df[columnNameHash] == entry.stem, columnNameCpu] = normalized_cpu_type
                except:
                    pass # sample with no cpu_type

                try:
                    verified = data['data']['attributes']['signature_info']['verified']
                    all_df.loc[all_df[columnNameHash] == entry.stem, 'code_sign'] = verified
                except:
                    pass # sample with no verified data
                
                try:
                    libs = data['data']['attributes']['macho_info'][0].get('libs', [])
                    for lib in libs:
                        lib_counts[lib] += 1  # Count every occurrence of each library
                except:
                    pass #sample with no imported libraries
                
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
                

        # all_df.to_csv('../Output/csv/src/all_df.csv', index=False)



        code_sign_verified_df = all_df.value_counts('code_sign')
        code_sign_verified_df = code_sign_verified_df.reset_index() #Get and index
        code_sign_verified_df.columns = ['code_sign', columnNameCount] 
        dfCountAndSave(code_sign_verified_df,'code_sign',len(all_df),'../Output/csv/code_sign_verified.csv')

        dfCountAndSave(lib_counts,'Library',len(all_df),'../Output/csv/lib_counts.csv')

    percentagesOverTheYears()
    getInfoRadareFunction()

    makeTableCPUComparation()




def createGraphicDensityAnex():
    """
    Generate and save entropy distribution histogram for binaries.
    """
    data = pd.read_csv('../Output/csv/src/die.csv') 

    entropy_values = data['Avg_Entropy']
    counts, bins = np.histogram(entropy_values, bins=50)

    # Create the bar plot with slight gaps
    plt.figure(figsize=(10, 6))
    bar_width = (bins[1] - bins[0]) * 0.9  # Set the width to 90% of the bin width for small gaps
    plt.bar(bins[:-1], counts, width=bar_width, color='black', align='edge')
    plt.xlabel('Entropy')
    plt.ylabel('Number of samples')
    
    plt.tight_layout()
    output_path = os.path.join(save_path, f'anex_entropy.pdf')
    plt.savefig(os.path.join(save_path, f'anex_entropy.pdf')) 
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_entropy_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)

def create_graphic_size_anex():
    """
    Generate and save size distribution histograms for dynamically- and statically-linked binaries.
    """

    data = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    dynamic_df = pd.read_csv('../Output/csv/dynamicInfo.csv') 
    
    filtered_data = data[data["file_type"] == "application/x-mach-binary"]
    filtered_data = filtered_data.dropna(subset=["Size"])
    print(filtered_data.head())
    filtered_data = filtered_data[filtered_data["Size"] != ""]
    filtered_data["Size_KB"] = filtered_data["Size"] / 1024
    filtered_data = filtered_data.merge(dynamic_df, on='Hash', how='left')

    # If the 'Linked' column has 'dynamically-linked' or 'statically-linked', use that to classify
    dynamic_sizes = filtered_data[filtered_data["Linked"] == "dynamically-linked"]["Size_KB"]
    static_sizes = filtered_data[filtered_data["Linked"] == "statically-linked"]["Size_KB"]
    unknown_sizes = filtered_data[filtered_data["Linked"] == "Unknown"]["Size_KB"]
    bins = np.logspace(np.log10(min(dynamic_sizes.min(), static_sizes.min(), unknown_sizes.min())), 
                    np.log10(max(dynamic_sizes.max(), static_sizes.max(), unknown_sizes.max())), 300)  # Increase bin count to 200

    dynamic_counts, bin_edges = np.histogram(dynamic_sizes, bins=bins)
    static_counts, _ = np.histogram(static_sizes, bins=bins)
    unknown_counts, _ = np.histogram(unknown_sizes, bins=bins)
    print(dynamic_counts," ",static_counts, " ",unknown_counts)
    plt.figure(figsize=(10, 8))

    plt.hist(dynamic_sizes, bins=np.logspace(np.log10(dynamic_sizes.min()), np.log10(dynamic_sizes.max()), 50), alpha=0.8, color='red', label='Dynamically linked',rwidth=0.5)
    plt.hist(static_sizes, bins=np.logspace(np.log10(static_sizes.min()), np.log10(static_sizes.max()), 50), alpha=1, color='blue', label='Statically linked',rwidth=0.5)
    plt.hist(unknown_sizes, bins=np.logspace(np.log10(unknown_sizes.min()), np.log10(unknown_sizes.max()), 50), alpha=1, color='grey', label='Unknown',rwidth=0.5)

    plt.yscale('log')
    plt.xscale('log')
    plt.xlabel('Size [KB]')
    plt.ylabel('Number of Samples')
    plt.legend(fontsize=10, loc='upper right')  
    
    plt.tight_layout()
    output_path = os.path.join(save_path, f'anex_size.pdf')
    plt.savefig(os.path.join(output_path))
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_size_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)



def create_graphic_symbols_anex():
    """
    Generate and save histogram of number of symbols imported per binary.
    """
    data = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    
    filtered_data = data[data["file_type"] == "application/x-mach-binary"]
    filtered_data = filtered_data.dropna(subset=["N_Symbols"])
    filtered_data = filtered_data[filtered_data["N_Symbols"] != ""]
    symbols_values = filtered_data["N_Symbols"]


    bins = np.logspace(0, 5, 100) 
    counts, bin_edges = np.histogram(symbols_values, bins=bins)

    plt.figure(figsize=(10, 8))
    bar_width = (bin_edges[1:] - bin_edges[:-1]) * 0.7  
    plt.bar(bin_edges[:-1], counts, width=bar_width, color='black', align='edge')


    plt.xscale('log')
    plt.xlabel('Number of symbols')
    plt.ylabel('Number of samples')
    

    output_path = os.path.join(save_path, f'symbols_size.pdf')
    plt.savefig(os.path.join(output_path))
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_symbols_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)


def create_graphic_function_imports():
    """
    Generate and save bar chart of most frequent imported functions.
    """

    data = pd.read_csv('../Output/csv/src/symbols_modified.csv')

    data = data.nlargest(50, columnNameCount)
    print(data['Symbol'].tail(10))
    data['Symbol'] = data['Symbol'].str.replace(r'^sym\.imp\.', '', regex=True)
    print(data['Symbol'].tail(10))
    total_count = 62022
    data[columnNamePercentage] = (data[columnNameCount] / total_count) * 100
    # Format the percentage values to two decimal places with rounding
    data[columnNamePercentage] = data[columnNamePercentage].apply(
        lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}"
    )

    fig, ax = plt.subplots(figsize=(7, 8))

    bars = ax.barh(data['Symbol'], data[columnNamePercentage].astype(float), color='black', height=0.2)  # Reduced bar height

    ax.set_xlabel('Percentage', fontsize=12, fontweight='bold') 
    ax.set_ylabel('Symbol', fontsize=12, fontweight='bold') 

    ax.tick_params(axis='y', labelsize=8)
    for label in ax.get_yticklabels():
        label.set_fontweight('bold') ¡

    ax.set_xticks([25, 50, 75, 90])
    ax.set_xticklabels(['25%', '50%', '75%', '90%'], fontsize=10, fontweight='bold') 
    ax.set_xlim(0, 90)  

    ax.set_ylim(len(data)-0.5, -0.5)
    plt.subplots_adjust(left=0.15, right=0.95, top=0.95, bottom=0.05)  # Reduce margins (left and right)
    plt.tight_layout(pad=0.1)

    output_path = os.path.join(save_path, f'imported_symbols.pdf')
    plt.savefig(output_path)
    plt.close(fig)
    cropped_output_path = os.path.join(save_path, f'imported_symbols_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)

def getLinked(output_dir):
    """
    Extract and classify binary linking type (dynamic vs static).

    Args:
        output_dir -- Directory containing JSON reports.
    """
    path = Path(output_dir)
    start_time = time.time()
    total_items = sum(1 for entry in path.rglob('*'))
    results = []
    with open('../Output/csv/dynamicInfo.csv', "w") as file:
        file.write(f'Hash,Linked\n')
    for i, entry in enumerate(path.rglob('*')):
        commonMethods.custom_progress_bar("Progress getInfoAboutEachBinary linked, " ,i + 1, total_items,start_time)
        file_hash = entry.stem
        
        if filters.filer_hash_alldata(file_hash):
            continue
        
        with open(entry) as f:
            data = json.load(f)
            
            try:
                magic_string = data['data']['attributes']['magic']
                libs = data['data']['attributes']['macho_info'][0].get('libs', [])
                if libs:
                    results.append({'Hash': file_hash, 'Linked': 'dynamically-linked'})
                elif magic_string:
                    match = re.search(r"flags:<([^>]+)>", magic_string)
                    if match:
                        flags = match.group(1).split('|')
                        if 'DYLDLINK' in flags:
                            results.append({'Hash': file_hash, 'Linked': 'dynamically-linked'})
                        elif 'NOUNDEFS' in flags:
                            results.append({'Hash': file_hash, 'Linked': 'statically-linked'})
                        else:
                            results.append({'Hash': file_hash, 'Linked': 'Unknown'})
                    else:
                        results.append({'Hash': file_hash, 'Linked': 'Unknown'})
                else:
                    results.append({'Hash': file_hash, 'Linked': 'Unknown'})

            except Exception as e:
                print(f"Error processing sample {file_hash}: {e}")
                results.append({'Hash': file_hash, 'Linked': 'Unknown'})

        # Create a DataFrame and export to CSV
        df = pd.DataFrame(results)
        df.to_csv('../Output/csv/dynamicInfo.csv', index=False)


if __name__ == '__main__':

    commonMethods.check_path_and_create(outputFolder)
    commonMethods.check_path_and_create(outputCSVFolder)
    commonMethods.check_path_and_create(outputCSVFolderSource)
    commonMethods.check_path_and_create(save_path)
    malware_df = None
    update = int(sys.argv[1]) 
    if update == 1: #This is in case you need to update the data otherwise put 0
        print("Update data") 
        commonMethods.remove_path(outputTxtFamily)
        VT_download_normal_report_and_behavior.main(commonMethods.hashesfile, output_dir,output_dir_behaviour_summary,config_file)#Download JSON of each sample
        passJSONToAvclass(output_dir,outputTxtFamily) 
        malware_df = parseMalwareAndFamily(outputTxtFamily) 


    malware_df = pd.read_csv(outputTxtFamily)  
    
    create_graphics_malware_behaviors(output_dir_behaviour_summary,malware_df,output_dir,update) #get info from behavior report from samples that have behavior
    create_graphics_malware_normal_report(output_dir,update) #get info from normal report from all samples


    createGraphicDensityAnex()  
    getLinked(output_dir) 
    create_graphic_size_anex() 
    create_graphic_symbols_anex() 
    create_graphic_function_imports() 

