import VT_download_normal_report_and_behavior
import getInfoRadare
import filters
import subprocess
import pandas as pd
from pathlib import Path
import json
import commonMethods #File
import requests
import time 
import mapperTechniquesToTactics #File
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from graphdatascience.graph.graph_object import Graph
from py2neo import Graph, Node, Relationship
from itertools import combinations
import numpy as np
import seaborn as sns
import networkx as nx
from networkx.drawing.nx_agraph import write_dot
import datetime
import sys
from collections import defaultdict
import plotly.express as px
import ast  # To convert the string list into a list
from matplotlib import rc
from sklearn.linear_model import LinearRegression
import math
from decimal import Decimal, ROUND_HALF_UP
import re

# Then, you can convert the PNG to PDF using an external library like ReportLab or Pillow
from PIL import Image

rc('font', family='serif', serif='Times New Roman', size=22)
plt.rcParams['text.usetex'] = False


outputFolder = "../Output"
outputCSVFolder =  "../Output/csv"
outputCSVFolderSource =  "../Output/csv/src"
outputTxtFamily = "../Output/Hashes_info/familyOfEachMalware.txt"
output_dir = '../Output/Hashes_info/VT_JSON'
output_dir_behaviour_summary = '../Output/Hashes_info/VT_MBCS_JSON'
# output_dir = '/mnt/DATASETS/macho-binaries-and-reports/reports/VT_JSON'
# output_dir_behaviour_summary = '/mnt/DATASETS/macho-binaries-and-reports/reports/VT_MBCS_JSON'
config_file = 'config.ini'
save_path = '../Output/Graphics/'
dot_path =  "../gephi/graphic.dot"
regression_dot_path =  "../gephi/graphic_regression.dot"

columnNameFirstSubmissionDate = "first_submission_date" 
columnNameHash = "Hash"
columnNameFamily = "Family"
columnNameTechnique = "Technique"
columnNameCount = "Count"
columnNameTechniqueX1 = "TechniqueX1"
columnNameTechniqueX2 = "TechniqueX2"
columnNameCoefficientRegression = "Regression Coeficient"
columnNameLastSubmissionDate = "last_submission_date"
columnNameTactic = "Tactic"
columnNameMalwareFamily = "Malware_Family"

columnNameCpu = "cpu_type"
columnNamePercentage = "% Over total"
columnNamePacked = "Packed"
columnNameAvgEntropy = "Avg_Entropy"
MITRE_ATTACK_DATA = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json').json()
TECHNIQUES = {technique['external_references'][0]['external_id']:technique['name'] for technique in MITRE_ATTACK_DATA['objects'] if technique['type'] == 'attack-pattern' and not technique.get('revoked')}



def generate_mitre_navigator_layout(mitre_df):
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
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    else:
        return None 


#To use this function you need to pip install avclass-malicialab 
def passJSONToAvclass(output_dir,outputTxtFamily):

    cmdCommand = f"avclass -d {output_dir} -o {outputTxtFamily}"   
    process = subprocess.Popen(cmdCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)

def getMalwareFamily(malware_df,hash):
    family = malware_df.loc[malware_df[columnNameHash] == hash, columnNameMalwareFamily].values[0] 
    family = family.split(':')[0]
    return family


def create_bar_chart(mitre_df, family_name, countMalware_df):    
    modified_mitre_df = mitre_df.copy()
    modified_mitre_df[columnNameTechnique] = modified_mitre_df[columnNameTechnique].apply(get_technique)
    modified_mitre_df = modified_mitre_df.dropna(subset=[columnNameTechnique])
    modified_mitre_df = modified_mitre_df.groupby([columnNameTechnique, columnNameFamily]).size().reset_index(name=columnNameCount)
    modified_mitre_df = modified_mitre_df.sort_values(by=columnNameCount)

    family_df = modified_mitre_df[modified_mitre_df[columnNameFamily] == family_name]

    fig, ax = plt.subplots(figsize=(12, len(family_df) * 0.5))  
    bars = ax.barh(family_df[columnNameTechnique], family_df[columnNameCount], color='skyblue')

    for bar in bars:
        width = bar.get_width()
        ax.text(width + 0.1, 
                bar.get_y() + bar.get_height() / 2,
                f'{int(width)}', 
                va='center',  
                ha='left')  


    count = countMalware_df.loc[countMalware_df[columnNameFamily] == family_name, columnNameCount].values[0]
    ax.set_title(f'Malware Family: {family_name} total samples of the family: {count}')
    ax.set_xlabel('Count')
    ax.set_ylabel('Technique')

    ax.invert_yaxis()

    plt.tight_layout()
    plt.savefig(os.path.join(save_path, f'{family_name}.pdf')) # Create bar chart for each family
    plt.close(fig)  


def addHashAndTechniqueRow(hash,malware_family,techniqueName,mitre_df,date):
    techniqueName = techniqueName['id']
    mask = (mitre_df[columnNameHash] == hash) & (mitre_df[columnNameFamily] == malware_family) & (mitre_df[columnNameTechnique] == techniqueName)
    if mitre_df.loc[mask].empty:
        mitre_df = pd.concat([pd.DataFrame([[hash,malware_family, techniqueName,1,date]], columns=[columnNameHash,columnNameFamily, columnNameTechnique,columnNameCount,columnNameFirstSubmissionDate]), mitre_df], ignore_index=True)
    return mitre_df

def addHashToAll(hash,malware_family,all_df,date):

    all_df = pd.concat([pd.DataFrame([[hash,malware_family, date]], columns=[columnNameHash,columnNameFamily, columnNameFirstSubmissionDate]), all_df], ignore_index=True)
    return all_df

def countFamilyMalwareWithData(malware_family,countMalware_df):
    mask = (countMalware_df[columnNameFamily] == malware_family) 
    try: 
        count = countMalware_df.loc[mask, columnNameCount].values[0]
        countMalware_df.loc[mask, columnNameCount] = int(count) + 1
    except:
        countMalware_df = pd.concat([pd.DataFrame([[malware_family, 1]], columns=[columnNameFamily, columnNameCount]), countMalware_df], ignore_index=True)
    
    return countMalware_df


def truncate(number, decimals=1):
    factor = 10.0 ** decimals
    return int(number * factor) / factor


def createHeatMap(correlation_df):
    correlation_df = correlation_df.dropna(subset=[columnNameCoefficientRegression])

    correlation_df.loc[:, columnNameCoefficientRegression] = correlation_df[columnNameCoefficientRegression].apply(lambda x: truncate(x,1))
    correlation_matrix = pd.pivot_table(correlation_df, values=columnNameCoefficientRegression, index=columnNameTechniqueX1, columns=columnNameTechniqueX2)

    plt.figure(figsize=(20, 16)) 
    sns.heatmap(correlation_matrix, annot=True, fmt=".1f", cmap='coolwarm', center=0,vmin=-1, vmax=1,
                    linewidths=.5, 
                    cbar_kws={"orientation": "vertical", "fraction": 0.02, "pad": 0.1})


    plt.title('Heatmap of Lineal Correlation Between Malware Techniques')
    plt.savefig(os.path.join(save_path, f'HeatMapCorrelation.pdf'), bbox_inches='tight', dpi=300)
    plt.close()


def calculateSingleCorrelation(df,columnX1,columnX2):
    std_dev_a = df[columnX1].std() 
    std_dev_b = df[columnX2].std()
    if std_dev_a != 0 and std_dev_b != 0:
        r = np.corrcoef(df[columnX1], df[columnX2])[0, 1]
        return r
    else:
        return None


def getFirstSubmissionDateOfHash(hash,path_normal_report):
    path = path_normal_report + "/" + hash
    with open(path) as f:
        data = json.load(f)
        first_submission_date = datetime.datetime.fromtimestamp( data['data']['attributes']['first_submission_date']).strftime('%Y-%m-%d')
        with open('../Output/csv/dates.csv', "a") as file:
            file.write(f'{hash},{first_submission_date}\n')
        return first_submission_date


def plot_mitre_data(mitre_df_part, save_name,title):
    fig, ax = plt.subplots(figsize=(30, 12), layout="constrained")
    ax.set(title=title)

    # Create levels with more separation for coinciding dates
    unique_dates = mitre_df_part['YearMonth'].unique()
    levels_dict = {}
    for date in unique_dates:
        count = len(mitre_df_part[mitre_df_part['YearMonth'] == date])
        levels_dict[date] = list(np.linspace(1, -1, count) * 20)  # Convert to list for pop()

    # Apply the levels based on the date
    levels = []
    for date in mitre_df_part['YearMonth']:
        level = levels_dict[date].pop(0)
        levels.append(level)
    
    # Plotting
    ax.vlines(mitre_df_part['YearMonth'], 0, levels, color="tab:blue")
    ax.axhline(0, color="black")
    ax.plot(mitre_df_part['YearMonth'], np.zeros_like(mitre_df_part['YearMonth']), "ko", mfc="white")

    # Annotate the lines with the family names
    for family, date, level in zip(mitre_df_part[columnNameFamily], mitre_df_part['YearMonth'], levels):
        ax.annotate(family, xy=(date, level),
                    xytext=(0, np.sign(level)*20), textcoords="offset points",
                    ha='center',
                    verticalalignment="bottom" if level > 0 else "top",
                    bbox=dict(boxstyle='round,pad=0.3', lw=0, fc=(1, 1, 1, 0.7)))

    ax.yaxis.set_visible(False)
    ax.spines[["left", "top", "right"]].set_visible(False)
    ax.margins(y=0.2)

    plt.xticks(rotation=45, ha='right')
    plt.savefig(os.path.join(save_path, save_name))
    plt.close(fig)

def comparationBetweenAllFamiliesAndBehavior(countMalware_Behavior_df,all_df):
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
            pass #No existe familia

    all_df[columnNameResult] = all_df[columnNameResult].fillna(0)
    all_df = all_df.sort_values(by=[columnNameCount],ascending=False)
    all_df.to_csv('../Output/csv/comparationBetweenAllFamiliesAndBehavior.csv',index=False)

def familiesWithoutBehavior(countMalware_Behavior_df, all_df):
    # Group `all_df` by Family and get total count for each family
    all_df = all_df.groupby([columnNameFamily])[columnNameFamily].size().reset_index(name=columnNameCount)
    
    # Prepare additional columns
    columnNameFraction = "Behavior/Total"
    columnNameResult = "Coefficient"
    columnNameMissingBehavior = "No_Behavior_Count"
    
    all_df[columnNameFraction] = None
    all_df[columnNameResult] = None
    all_df[columnNameMissingBehavior] = None  # New column for samples without behavior

    for index, row in countMalware_Behavior_df.iterrows():
        family = row[columnNameFamily]
        count_behavior = row[columnNameCount]
        mask = (all_df[columnNameFamily] == family)
        
        try:
            count_all = all_df.loc[mask, columnNameCount].values[0]
            # Populate existing columns
            all_df.loc[mask, columnNameFraction] = f"{count_behavior}/{count_all}"
            all_df.loc[mask, columnNameResult] = count_behavior / count_all
            # Calculate samples without behavior
            all_df.loc[mask, columnNameMissingBehavior] = count_all - count_behavior
        except:
            pass  # Family not present

    # Fill missing values in columns
    all_df[columnNameResult] = all_df[columnNameResult].fillna(0)
    all_df[columnNameMissingBehavior] = all_df[columnNameMissingBehavior].fillna(all_df[columnNameCount])

    # Sort by families with the most samples without behavior
    all_df = all_df.sort_values(by=[columnNameMissingBehavior], ascending=False)
    
    # Save result to CSV
    all_df.to_csv('../Output/csv/familiesWithoutBehavior.csv', index=False)



def topTTPUsed(mitre_df,total_bianries_withmitre_info):
    modified_mitre_df = mitre_df.copy()
    
    df_val_counts = modified_mitre_df.value_counts(columnNameTechnique)
    df_value_counts_reset = df_val_counts.reset_index() #Get and index
    df_value_counts_reset.columns = [columnNameTechnique, 'Count'] 
    df_value_counts_reset["Tactic"] = df_value_counts_reset[columnNameTechnique].map( lambda x: mapperTechniquesToTactics.get_technique_to_tactic().get(x, [])) #Create column Tactic for each Technique to identify
    df_value_counts_reset[columnNameTechnique] = df_value_counts_reset[columnNameTechnique].apply(get_technique)
    df_value_counts_reset = df_value_counts_reset.dropna(subset=[columnNameTechnique])
    df_value_counts_reset[columnNamePercentage] = (df_value_counts_reset["Count"].astype(float) /int(total_bianries_withmitre_info))*100
    # df_value_counts_reset[columnNamePercentage]  = df_value_counts_reset[columnNamePercentage].apply(lambda x: float("{:.4f}".format(x)))
    print("executed")
    df_value_counts_reset[columnNamePercentage] = df_value_counts_reset[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")

    df_value_counts_reset.to_csv('../Output/csv/topTTPUsed.csv', index=False)
    print("topTTPUsed")

def split_tactics(row):
    tactic_str = row[columnNameTactic]
    tactics_list = [n.strip() for n in tactic_str]
    # Create a new DataFrame for each tactic, repeating the other columns for each tactic
    expanded_rows = pd.DataFrame({
        **{col: [row[col]] * len(tactics_list) for col in row.index},  # Repeat all original columns
        'Tactic': tactics_list  # Replace the Tactic column with the individual tactics
    })
    return expanded_rows


def tacticDistribution(mitre_df,total_bianries_withmitre_info):
    modified_mitre_df = mitre_df.copy()
    modified_mitre_df[columnNameTactic] = modified_mitre_df[columnNameTechnique].map( lambda x: mapperTechniquesToTactics.get_technique_to_tactic().get(x, [])) #Create column Tactic for each Technique to identify

    # Apply the function to each row and concatenate the results
    df_expanded = pd.concat([split_tactics(row) for _, row in modified_mitre_df.iterrows()], ignore_index=True)

    df_expanded = df_expanded.drop_duplicates(subset=[columnNameHash,columnNameTactic])
    df_expanded = df_expanded.value_counts(columnNameTactic)
    df_expanded = df_expanded.reset_index() #Get and index
    df_expanded.columns = [columnNameTactic, columnNameCount] 
    dfCountAndSave(df_expanded,columnNameTactic,int(total_bianries_withmitre_info) ,'../Output/csv/tactic_disctribution.csv')

    # showBarsTacticDistribution(df_expanded)


def showBarsTacticDistribution(tacticDistribution_df):

    
    custom_order = ['Initial Access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 
                'credential-access', 'discovery', 'lateral-movement', 'collection','command-and-control', 'exfiltration', 'impact']
    

    tacticDistribution_df[columnNameTactic] = pd.Categorical(
        tacticDistribution_df[columnNameTactic],
        categories=[name for name in custom_order],  # Use original format with hyphens
        ordered=True
    )
    tacticDistribution_df = tacticDistribution_df.dropna(subset=[columnNameTactic]).sort_values(by=columnNameTactic)

    tacticDistribution_df[columnNameTactic] = (
        tacticDistribution_df[columnNameTactic]
        .str.replace('-', ' ')          # Remove hyphens
        .str.title()                    # Capitalize each word
    )

    tacticDistribution_df[columnNamePercentage] = tacticDistribution_df[columnNamePercentage].astype(float) *100
    tacticDistribution_df[columnNamePercentage] = tacticDistribution_df[columnNamePercentage].apply(lambda x: float("{:.2f}".format(x)))

    print(tacticDistribution_df)
    fig, ax = plt.subplots(figsize=(20, len(tacticDistribution_df) * 0.9))
    bars = ax.bar(tacticDistribution_df[columnNameTactic], tacticDistribution_df[columnNamePercentage], color='skyblue')

    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, 
        height + 0.1, 
        f'{float(height)}%',  
        ha='center', 
        va='bottom',
        fontsize=28) 


    ax.set_xlabel('Tactic', fontsize=28)  # Replace 14 with your desired font size
    ax.set_ylabel('Percentage', fontsize=28)  # Replace 14 with your desired font size

    plt.xticks(rotation=45, ha='right', fontsize=24)  # Adjust fontsize as needed 
    plt.tight_layout()  
    plt.savefig(os.path.join(save_path, 'TacticDistribution.pdf'))
    plt.close(fig)




def create_gantt_chart_by_tactic():
    ttps_time_df = pd.read_csv('../Output/csv/ttps_time.csv')
    
    ttps_time_df[columnNameFirstSubmissionDate] = pd.to_datetime(ttps_time_df[columnNameFirstSubmissionDate])
    ttps_time_df[columnNameLastSubmissionDate] = ttps_time_df[columnNameLastSubmissionDate].fillna(ttps_time_df[columnNameFirstSubmissionDate])
    ttps_time_df[columnNameLastSubmissionDate] = pd.to_datetime(ttps_time_df[columnNameLastSubmissionDate])
    
    # Extract only the first tactic from the list for each entry
    ttps_time_df[columnNameTactic] = ttps_time_df[columnNameTactic].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)
    ttps_time_df['Tactic'] = ttps_time_df[columnNameTactic].apply(lambda x: x[0] if isinstance(x, list) and len(x) > 0 else None)
    
    # Prepare the DataFrame for Gantt chart
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
        x=0.01,     # Position it near the left edge
        y=0.01,     # Position it near the bottom edge
        xanchor="left",
        yanchor="bottom"
    )
)
    
    fig.update_yaxes(showticklabels=False)

    fig.update_xaxes(
        range=[ttps_time_df['Start'].min(), ttps_time_df['Finish'].max()],
        tickangle=45,
        dtick="M6",
        tickformat="%Y-%m",  # Format for x-axis dates
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
                text=row['Task'],  # Label with the task name
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

    # Use pdfcrop to crop the PDF automatically
    # cropped_output_path = os.path.join(save_path, "gantt_chart_by_tactic_cropped.pdf")
    # subprocess.run(["pdfcrop", os.path.join(save_path, "gantt_chart_by_tactic.pdf"), cropped_output_path])

def cheeseArquitecture():
    cpu_type_df = pd.read_csv('../Output/csv/radare_cpu_type')

    def custom_autopct(pct):
        return ('%.1f%%' % pct) if pct > 0.1 else '%.3f%%' % pct  # Smaller slices show more precision

    plt.figure(figsize=(10, 8))
    wedges, texts, autotexts = plt.pie(
        cpu_type_df['Count'], 
        labels=cpu_type_df['cpu_type'], 
        autopct=custom_autopct,  
        startangle=140, 
        explode=[0.1 if value < 1000 else 0 for value in cpu_type_df['Count']], 
        labeldistance=1.05,  
        pctdistance=0.8,     
        textprops={'fontsize': 21}
    )

    for i, (text, atext) in enumerate(zip(texts, autotexts)):
        if cpu_type_df['% Over total'][i] == 0.0013:  # Detect the 0.1% slice
            # Adjust the percentage text position
            atext.set_fontsize(21)
            atext.set_position((atext.get_position()[0], atext.get_position()[1] + 0.01))  # Move percentage label up
            # Adjust the architecture label position
            text.set_position((text.get_position()[0], text.get_position()[1] + 0.05))  # Move architecture label up
        elif cpu_type_df['% Over total'][i] == 0.0033:  # Detect the 0.3% slice
            # Adjust the percentage text position
            atext.set_fontsize(21)
            atext.set_position((atext.get_position()[0], atext.get_position()[1] + 0.01))  # Move percentage label up
            # Adjust the architecture label position
            text.set_position((text.get_position()[0], text.get_position()[1] + 0.1))  # Move architecture label up

    plt.axis('equal')
    plt.savefig(os.path.join(save_path, "cheeseArquitecture.pdf"))




def percentagesOverTheYears():
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


def analyze_group(df, packed_status):
    print(f"\n--- {packed_status.upper()} SAMPLES ---")
    total_samples = df[columnNameHash].nunique()
    # Top 10 most used techniques
    top_techniques = df.groupby('Technique').size().reset_index(name='count')
    top_techniques = top_techniques.sort_values(by='count', ascending=False).head(10)
    print("\nTop 10 most used techniques:")
    top_techniques[columnNameTechnique] = top_techniques[columnNameTechnique].apply(get_technique)

    top_techniques['total_count'] = total_samples
    top_techniques['% over total'] = (top_techniques['count'] / total_samples) * 100
    top_techniques.to_csv('../Output/csv/'+packed_status + 'TopTechniques.csv', index=False)
    
    # Earliest and latest submission dates
    earliest_date = df['first_submission_date'].min()
    latest_date = df['first_submission_date'].max()
    print(f"\nEarliest submission date: {earliest_date}")
    print(f"Latest submission date: {latest_date}")
    
    # Top families of malware
    df = df.drop_duplicates(subset=[columnNameHash])

    top_families = df.groupby('Family').size().reset_index(name='count')
    top_families = top_families.sort_values(by='count', ascending=False).head(10)

    top_families['total_count'] = total_samples
    top_families['% over total'] = (top_families['count'] / total_samples) * 100
    top_families.to_csv('../Output/csv/'+packed_status + 'TopFamilies.csv', index=False)


def getInfoRadareFunction():
    
    radare_df = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    # print("before quit: " ,len(radare_df))
    # radare_df = radare_df[radare_df[columnNameHash] != 'f4368ec6e859231872f76dfa62b75ee1']
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


    radare_df['Complexity'] = pd.to_numeric(radare_df['Complexity'], errors='coerce')
    radare_df['Size'] = pd.to_numeric(radare_df['Size'], errors='coerce')
    radare_df['N_Symbols'] = pd.to_numeric(radare_df['N_Symbols'], errors='coerce')
    #Count of Stripped vs. Non-Stripped Files
    plt.figure(figsize=(7, 5))
    sns.countplot(x='Stripped', data=radare_df)
    plt.title("Count of Stripped vs. Non-Stripped Files")
    plt.xlabel("Stripped")
    plt.ylabel("Count")
    plt.savefig(os.path.join(save_path, "strippedvsnonstripped.pdf"))
    plt.close()

    # KDE Plot for Complexity by Stripped Status
    plt.figure(figsize=(8, 6))
    sns.kdeplot(data=radare_df, x='Complexity', hue='Stripped', fill=True, common_norm=False, alpha=0.6)
    plt.xlabel('Complexity')
    plt.ylabel('Density')
    plt.title('Complexity Distribution by Stripped Status')
    plt.legend(title='Stripped', loc='upper right', labels=['Not Stripped', 'Stripped'])  # Ensure correct labels are set
    plt.savefig(os.path.join(save_path, "ComplexityDensityPlot_Stripped.pdf"))
    plt.close()


    # Scatter Plot of Size vs. Complexity
    plt.figure(figsize=(10, 5))
    sns.scatterplot(x='Size', y='Complexity', data=radare_df, alpha=0.6)
    plt.title("Size vs. Complexity")
    plt.xlabel("Size (bytes)")
    plt.ylabel("Complexity")
    plt.savefig(os.path.join(save_path, "size_vs_complexity.pdf"))
    plt.close()

    plt.figure(figsize=(10, 5))
    sns.regplot(x='Size', y='Complexity', data=radare_df, scatter_kws={'alpha':0.6}, line_kws={"color": "red"})
    plt.title("Size vs. Complexity with Regression Line")
    plt.xlabel("Size (bytes)")
    plt.ylabel("Complexity")
    plt.grid(True)
    plt.savefig(os.path.join(save_path, "size_vs_complexity2.pdf"))
    plt.close()

    # Scatter Plot for Number of Symbols vs Complexity
    plt.figure(figsize=(10, 5))
    sns.scatterplot(x='N_Symbols', y='Complexity', data=radare_df, alpha=0.6)
    plt.title("Number of Symbols vs Complexity")
    plt.xlabel("Number of Symbols")
    plt.ylabel("Complexity")
    plt.grid(True)
    plt.savefig(os.path.join(save_path, "numofsymbolsvscomplexity.pdf"))
    plt.close()




    radare_df['Complexity_Level'] = pd.qcut(radare_df['Complexity'], q=3, labels=["Low", "Medium", "High"])

    complexity_symbols_summary = radare_df.groupby('Complexity_Level', observed=True)['N_Symbols'].mean().reset_index()
    complexity_symbols_summary.columns = ['Complexity Level', 'Average Number of Symbols']

    print(complexity_symbols_summary)

def packedCount():
    die_df = pd.read_csv('../Output/csv/src/die.csv')
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    die_df = die_df[~die_df[columnNameHash].apply(filters.filer_hash_alldata)]
    all_df = all_df[~all_df[columnNameHash].apply(filters.filer_hash_alldata)]
    
    hashes_in_all_df = all_df[columnNameHash].unique()  # Get all unique hashes from all_df
    die_df = die_df[die_df[columnNameHash].isin(hashes_in_all_df)] 
    df_val_counts = die_df.value_counts(columnNamePacked)
    df_value_counts_reset = df_val_counts.reset_index() #Get and index
    df_value_counts_reset.columns = [columnNamePacked, 'Count'] 
    df_value_counts_reset[columnNamePercentage] = (df_value_counts_reset["Count"].astype(float) /int(df_value_counts_reset['Count'].sum()))*100
    # df_value_counts_reset[columnNamePercentage]  = df_value_counts_reset[columnNamePercentage].apply(lambda x: float("{:.4f}".format(x)))
    df_value_counts_reset[columnNamePercentage] = df_value_counts_reset[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")
    df_value_counts_reset.to_csv('../Output/csv/packed_count.csv', index=False)


def makeTableCPUComparation():
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
    
    # Map "packed" and "not packed" to True and False in packed_df
    packed_df['Packed'] = packed_df['Packed'].map({'packed': True, 'not packed': False})
    stripped_df = stripped_df.dropna(subset=['Stripped'])
    print("Unique values in 'Stripped' before mapping:", stripped_df['Stripped'].unique())

    # Convert Stripped column to boolean values if necessary
    stripped_df['Stripped'] = stripped_df['Stripped'].replace({'True': True, 'False': False})
    stripped_df['Stripped'] = stripped_df['Stripped'].astype(bool)

    # Merge the 'packed' column into all_df based on 'columnHash'
    all_df = pd.merge(all_df, packed_df, on=columnNameHash, how='left')
    
    # Merge the 'stripped' column into all_df based on 'columnHash'
    all_df = pd.merge(all_df, stripped_df, on=columnNameHash, how='left')

    all_df['HasBehavior'] = all_df[columnNameHash].isin(behavior_df[columnNameHash])

    print(len(all_df))
    print(all_df.head())

    # Create summary statistics by CPU type
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
    # Display or further process summary_df as needed
    


def dfCountAndSave(dictordf,columnNameItem,total_items,pathToSave):
    if isinstance(dictordf, dict): #The object is a dictionary so convert to DF
        dict_df = pd.DataFrame(list(dictordf.items()), columns=[columnNameItem, columnNameCount])
    else:
        dict_df = dictordf

    dict_df[columnNamePercentage] = (dict_df[columnNameCount].astype(float) / total_items ) * 100
    # dict_df[columnNamePercentage]  = dict_df[columnNamePercentage].apply(lambda x: float("{:.4f}".format(x)))
    dict_df[columnNamePercentage] = dict_df[columnNamePercentage].apply(
    lambda x: f"{Decimal(x).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%")
    dict_df = dict_df.sort_values(by=columnNameCount, ascending=False)
    dict_df.to_csv(pathToSave, index=False)




def createGraphicsMalwareBehaviors(path,malware_df,path_normal_report,update):
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

    packedCount()

    #Create graphics
    total_bianries_withmitre_info = mitre_df[columnNameHash].nunique()
    
    topTTPUsed(mitre_df,total_bianries_withmitre_info)
    tacticDistribution(mitre_df,total_bianries_withmitre_info)
    create_gantt_chart_by_tactic() 

    
    
    comparationBetweenAllFamiliesAndBehavior(countMalware_df,all_df)
    familiesWithoutBehavior(countMalware_df, all_df)
    generate_mitre_navigator_layout(mitre_df)



def normalize_cpu_type(cpu_type):
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
    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')
    df = df[~df[columnNameHash].isin(ios_hashes_df[columnNameHash])]
    return df



def createGraphicsMalwareNormalReport(output_dir,update):
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
    data = pd.read_csv('../Output/csv/src/die.csv')  # Replace with your file path

    # Extract the entropy column
    entropy_values = data['Avg_Entropy']

    counts, bins = np.histogram(entropy_values, bins=50)

    # Create the bar plot with slight gaps
    plt.figure(figsize=(10, 6))
    bar_width = (bins[1] - bins[0]) * 0.9  # Set the width to 90% of the bin width for small gaps
    plt.bar(bins[:-1], counts, width=bar_width, color='black', align='edge')


    # Set titles and labels to match the provided image
    # plt.title('Entropy distribution')
    plt.xlabel('Entropy')
    plt.ylabel('Number of samples')
    
    plt.tight_layout()
    # Display the plot
    output_path = os.path.join(save_path, f'anex_entropy.pdf')
    plt.savefig(os.path.join(save_path, f'anex_entropy.pdf')) # Create bar chart for each family
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_entropy_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)

def createGraphicSizeAnex():

    data = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    dynamic_df = pd.read_csv('../Output/csv/dynamicInfo.csv') 
    
    filtered_data = data[data["file_type"] == "application/x-mach-binary"]
    filtered_data = filtered_data.dropna(subset=["Size"])
    print(filtered_data.head())
    filtered_data = filtered_data[filtered_data["Size"] != ""]
    # Extract the "Size" column
    filtered_data["Size_KB"] = filtered_data["Size"] / 1024
    size_values = filtered_data["Size_KB"]


    filtered_data = filtered_data.merge(dynamic_df, on='Hash', how='left')

    # Now, instead of using "Type", use "Linked" as the column name
    # If the 'Linked' column has 'dynamically-linked' or 'statically-linked', use that to classify

    dynamic_sizes = filtered_data[filtered_data["Linked"] == "dynamically-linked"]["Size_KB"]
    static_sizes = filtered_data[filtered_data["Linked"] == "statically-linked"]["Size_KB"]
    unknown_sizes = filtered_data[filtered_data["Linked"] == "Unknown"]["Size_KB"]
    # bins = np.logspace(0, 5, 100)  # Logarithmic bins from 10^0 to 10^5
    # counts, bin_edges = np.histogram(size_values, bins=bins)
    # Increase the number of bins to have more bars
    bins = np.logspace(np.log10(min(dynamic_sizes.min(), static_sizes.min(), unknown_sizes.min())), 
                    np.log10(max(dynamic_sizes.max(), static_sizes.max(), unknown_sizes.max())), 300)  # Increase bin count to 200

    # Calculate the histogram
    dynamic_counts, bin_edges = np.histogram(dynamic_sizes, bins=bins)
    static_counts, _ = np.histogram(static_sizes, bins=bins)
    unknown_counts, _ = np.histogram(unknown_sizes, bins=bins)
    print(dynamic_counts," ",static_counts, " ",unknown_counts)
    # Create the bar plot with narrower bars
    plt.figure(figsize=(10, 8))
    # bar_width = (bin_edges[1:] - bin_edges[:-1]) * 0.6
    # plt.bar(bin_edges[:-1], counts, width=bar_width, color='black', align='edge')

    plt.hist(dynamic_sizes, bins=np.logspace(np.log10(dynamic_sizes.min()), np.log10(dynamic_sizes.max()), 50), alpha=0.8, color='red', label='Dynamically linked',rwidth=0.5)
    plt.hist(static_sizes, bins=np.logspace(np.log10(static_sizes.min()), np.log10(static_sizes.max()), 50), alpha=1, color='blue', label='Statically linked',rwidth=0.5)
    plt.hist(unknown_sizes, bins=np.logspace(np.log10(unknown_sizes.min()), np.log10(unknown_sizes.max()), 50), alpha=1, color='grey', label='Unknown',rwidth=0.5)

    # Set logarithmic scale and labels
    plt.yscale('log')
    plt.xscale('log')
    plt.xlabel('Size [KB]')
    plt.ylabel('Number of Samples')
    plt.legend(fontsize=10, loc='upper right')  # Add legend with proper labels
    
    plt.tight_layout()
    # Display the plot
    output_path = os.path.join(save_path, f'anex_size.pdf')
    plt.savefig(os.path.join(output_path)) # Create bar chart for each family
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_size_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)



def createGraphicSymbolsAnex():

    data = pd.read_csv('../Output/csv/src/radare_not_ios.csv')
    
    filtered_data = data[data["file_type"] == "application/x-mach-binary"]
    filtered_data = filtered_data.dropna(subset=["N_Symbols"])
    filtered_data = filtered_data[filtered_data["N_Symbols"] != ""]
    # Extract the "Size" column
    symbols_values = filtered_data["N_Symbols"]


    # Calculate the histogram for size values
    bins = np.logspace(0, 5, 100)  # Logarithmic bins from 10^0 to 10^5
    counts, bin_edges = np.histogram(symbols_values, bins=bins)

    # Create the bar plot with narrower bars
    plt.figure(figsize=(10, 8))
    bar_width = (bin_edges[1:] - bin_edges[:-1]) * 0.7  # Reduce bar width to 70% of bin width
    plt.bar(bin_edges[:-1], counts, width=bar_width, color='black', align='edge')


    plt.xscale('log')
    # Set titles and labels to match the provided image
    # plt.title('Number of symbols imported')
    plt.xlabel('Number of symbols')
    plt.ylabel('Number of samples')
    

    # Display the plot
    output_path = os.path.join(save_path, f'symbols_size.pdf')
    plt.savefig(os.path.join(output_path)) # Create bar chart for each family
    plt.close()

    cropped_output_path = os.path.join(save_path, f'anex_symbols_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)


def createGraphicFunctionImports():
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

    # Set a smaller figure size
    fig, ax = plt.subplots(figsize=(7, 8))

    # Create horizontal bar plot with smaller bar width
    bars = ax.barh(data['Symbol'], data[columnNamePercentage].astype(float), color='black', height=0.2)  # Reduced bar height

    # # Add smaller font percentage labels to each bar
    # for bar in bars:
    #     width = bar.get_width()
    #     ax.text(width + 0.1, 
    #             bar.get_y() + bar.get_height() / 2,
    #             f'{width:.2f}%',  # Format to 2 decimal places for percentages
    #             va='center', 
    #             ha='left', 
    #             fontsize=8)  # Set smaller font size for bar labels

    # Set title and labels with smaller font sizes and bold text
    ax.set_xlabel('Percentage', fontsize=12, fontweight='bold')  # Bold x-axis label
    ax.set_ylabel('Symbol', fontsize=12, fontweight='bold')  # Bold y-axis label

    # Adjust tick labels font size for y-axis and make them bold
    ax.tick_params(axis='y', labelsize=8)
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')  # Make y-axis tick labels bold

    # Set specific x-axis ticks at 25%, 50%, and 75%
    ax.set_xticks([25, 50, 75, 90])
    ax.set_xticklabels(['25%', '50%', '75%', '90%'], fontsize=10, fontweight='bold')  # Bold x-axis ticks
    ax.set_xlim(0, 90)  # Limit x-axis to 90%

    ax.set_ylim(len(data)-0.5, -0.5)
    # ax.invert_yaxis()
    # Adjust margins and padding to remove extra space around the plot
    plt.subplots_adjust(left=0.15, right=0.95, top=0.95, bottom=0.05)  # Reduce margins (left and right)

    # Apply tight layout to make sure everything fits without extra space
    plt.tight_layout(pad=0.1)

    output_path = os.path.join(save_path, f'imported_symbols.pdf')
    plt.savefig(output_path)
    plt.close(fig)

    # Optionally, crop the saved PDF to fit the content
    cropped_output_path = os.path.join(save_path, f'imported_symbols_cropped.pdf')
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)

def getLinked(output_dir):
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

    commonMethods.checkPathAndCreates(outputFolder)
    commonMethods.checkPathAndCreates(outputCSVFolder)
    commonMethods.checkPathAndCreates(outputCSVFolderSource)
    commonMethods.checkPathAndCreates(save_path)
    malware_df = None
    update = int(sys.argv[1]) 
    if update == 1: #This is in case you need to update the data otherwise put 0
        print("Update data") 
        commonMethods.removePath(outputTxtFamily)
        VT_download_normal_report_and_behavior.main(commonMethods.hashesfile, output_dir,output_dir_behaviour_summary,config_file)#Download JSON of each sample
        passJSONToAvclass(output_dir,outputTxtFamily) 
        malware_df = parseMalwareAndFamily(outputTxtFamily) 


    malware_df = pd.read_csv(outputTxtFamily)  
    
    createGraphicsMalwareBehaviors(output_dir_behaviour_summary,malware_df,output_dir,update) #get info from behavior report from samples that have behavior
    getInfoRadare.main() 
    createGraphicsMalwareNormalReport(output_dir,update) #get info from normal report from all samples


    createGraphicDensityAnex()  
    getLinked(output_dir) 
    createGraphicSizeAnex() 
    createGraphicSymbolsAnex() 
    createGraphicFunctionImports() 

