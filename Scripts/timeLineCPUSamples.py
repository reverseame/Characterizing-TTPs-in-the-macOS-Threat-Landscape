
import subprocess
import pandas as pd
from pathlib import Path
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib import rc
from sklearn.linear_model import LinearRegression
import seaborn as sns
import numpy as np
import matplotlib.ticker as ticker
from matplotlib.ticker import LogLocator, NullFormatter

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


def deleteIOSRows(df):
    ios_hashes_df = pd.read_csv('../Output/csv/src/iOShashes.csv')
    df = df[~df[columnNameHash].isin(ios_hashes_df[columnNameHash])]
    return df



def timeLineCPUSamplesWithPercentageWithoutBehaviorTWOBARSBUTSECONDFUNC():
    # Load Data
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    print(len(all_df))
    all_hashes_with_info = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')
    print(len(all_hashes_with_info))
    # Identify "w/o behavior" (previously "Unknown") hashes
    known_hashes = set(all_hashes_with_info[columnNameHash])
    all_df['CPU_Type'] = all_df[columnNameHash].apply(lambda h: 'Without behavior' if h not in known_hashes else None)

    # Assign existing CPU types where available
    all_df.loc[all_df['CPU_Type'].isna(), 'CPU_Type'] = all_df[columnNameCpu]

    # Remove rows with empty CPU types
    all_df = all_df.dropna(subset=['CPU_Type'])
    all_df['CPU_Type'] = all_df['CPU_Type'].astype(str).str.strip()
    all_df = all_df[all_df['CPU_Type'] != ""]

    # Convert dates and extract years
    all_df[columnNameFirstSubmissionDate] = pd.to_datetime(all_df[columnNameFirstSubmissionDate])
    all_df['Year'] = all_df[columnNameFirstSubmissionDate].dt.year

    # Aggregate Data
    grouped_df = all_df.groupby(['Year', 'CPU_Type']).size().reset_index(name='count')
    counts = grouped_df.groupby('CPU_Type')['count'].sum()

    # Sort CPU types by total count (descending)
    sorted_cpu_types = counts.sort_values(ascending=False).index.tolist()

    # Define colors
    cpu_colors = {
    'x86_64': '#1f77b4',          # Blue
    'ARM_64': '#ff7f0e',          # Orange
    'x86_64, ARM_64': '#2ca02c',  # Green
    'x86_64, PPC_32': '#d62728',  # Red
    'PPC_32': '#9467bd',          # Purple
    'ARM_32': '#8c564b',          # Brown
    'PPC_64': '#e377c2',          # Pink
    'x86_64, PPC_64, PPC_32': '#8c00ff',  # **Bright Violet** (changed from dark orange)
    'x86_32': '#17becf',          # Cyan
    'x86_32, PPC_32': '#bcbd22',  # Yellow-green
    'Without behavior': '#7f7f7f' # Medium gray for better contrast
}




    # Ensure color list follows sorted CPU types
    # color_list = [cpu_colors.get(cpu, '#7f7f7f') for cpu in sorted_cpu_types]

    # Pivot table for stacking
    pivot_df = all_df.groupby(['Year', 'CPU_Type']).size().unstack(fill_value=0)

    # Ensure all years are included
    all_years = list(range(all_df['Year'].min(), all_df['Year'].max() + 1))
    pivot_df = pivot_df.reindex(all_years, fill_value=0)

    
    # Extract "w/o behavior" data separately
    wo_behavior_df = pivot_df['Without behavior'] if 'Without behavior' in pivot_df.columns else pd.Series(0, index=pivot_df.index)

    # Remove "w/o behavior" from stacked CPU types
    pivot_df = pivot_df.drop(columns=['Without behavior'], errors='ignore')

    # pivot_df = pivot_df + 1
    # wo_behavior_df = wo_behavior_df + 1
    # wo_behavior_df.loc[wo_behavior_df.index == 2008] += 1
    print(pivot_df)
    print(wo_behavior_df)
    # Plot
    fig, ax = plt.subplots(figsize=(13, 7))

    # Plot stacked CPU types
    pivot_df.plot(kind='bar', stacked=True, ax=ax, width=0.4, color=cpu_colors, alpha=0.7, position=1)

    # Plot "w/o behavior" separately
    wo_behavior_df.plot(kind='bar', ax=ax, width=0.4, color='#B0B0B0', alpha=0.7, position=0)
    
    

    # Log scale for better visibility
    # ax.set_yscale('symlog', linthresh=1)

    # max_stack = pivot_df.sum(axis=1).max()
    # max_wo_behavior = wo_behavior_df.max()
    # y_max = max(max_stack, max_wo_behavior)
    #     # Set limits from 1 to your maximum
    # ax.set_ylim(1, y_max)

    # # Configure major log ticks (only powers of 10)
    # ax.yaxis.set_major_locator(ticker.LogLocator(base=10.0))
    # ax.yaxis.set_minor_locator(ticker.LogLocator(base=10.0, subs='auto'))
    # ax.yaxis.set_minor_formatter(ticker.NullFormatter())

    # # Move 10⁰ label (value=1) slightly down
    # # Offset the 10^0 tick label slightly upward
    # for label in ax.get_yticklabels():
    #     if label.get_text() in ['1', '10^0']:  # handle both plain '1' and scientific format
    #         label.set_y(label.get_position()[1] + 0.05)  # Adjust this value as needed


    # Set symlog scale
    ax.set_yscale('symlog', linthresh=1)

    # Set proper y-limits based on your data
    y_max = max(pivot_df.sum(axis=1).max(), wo_behavior_df.max())
    ax.set_ylim(1, y_max)

    # Format ticks normally
    ax.yaxis.set_major_locator(ticker.LogLocator(base=10.0))
    ax.yaxis.set_minor_locator(ticker.LogLocator(base=10.0, subs='auto', numticks=100))
    ax.yaxis.set_minor_formatter(ticker.NullFormatter())

    # Remove gridlines completely (no horizontal lines)
    ax.grid(False)

    # Manually adjust label position of 10^0 (which is 1) slightly higher
    for label in ax.get_yticklabels():
        if label.get_text() in ['1', '10⁰', r'$10^0$']:
            label.set_verticalalignment('bottom')  # Move label a bit upward
            label.set_y(0.05)  # Fine-tune this as needed (try with small increments like 0.05)

    # ax.set_yscale('symlog', linthresh=10)
    # ax.set_yscale('log')
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of Samples')
    ax.set_xticks(range(len(all_years)))
    ax.set_xticklabels(all_years, rotation=45)

    # Legend: Sort labels by total count and arrange into two columns
    handles, labels = ax.get_legend_handles_labels()
    sorted_labels = [label for label in sorted_cpu_types]
    sorted_handles = [handles[labels.index(label)] for label in sorted_cpu_types]

    ax.legend(
    sorted_handles, sorted_labels, title='CPU Type', loc='upper left',
    bbox_to_anchor=(0, 1.02), fontsize='x-small', frameon=True, ncol=2, borderaxespad=0.2
)


    plt.tight_layout()

    # Save cropped PDF
    output_path = os.path.join(save_path, "timeLineCPUSamplesWithPercentage.pdf")
    plt.savefig(output_path)
    plt.close()
    cropped_output_path = os.path.join(save_path, "timeLineCPUAndBehTwoColum.pdf")
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)


def timeLineSandboxCPUTypeDistribution():
    # Load Data
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    all_hashes_with_info = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')
    sandbox_df = pd.read_csv('../Output/csv/src/sandbox_df.csv')  # Sandbox data

    # Identify "w/o behavior" hashes
    known_hashes = set(all_hashes_with_info[columnNameHash])
    all_df['CPU_Type'] = all_df[columnNameHash].apply(lambda h: 'w/o behavior' if h not in known_hashes else None)

    # Assign existing CPU types
    all_df.loc[all_df['CPU_Type'].isna(), 'CPU_Type'] = all_df[columnNameCpu].str.strip()

    # Filter sandboxes to only include the desired ones
    desired_sandboxes = ['VirusTotal Box of Apples', 'OS X Sandbox', 'Zenbox macOS']
    sandbox_df = sandbox_df[sandbox_df['Sandbox'].isin(desired_sandboxes)]

    sandbox_df['Sandbox'] = sandbox_df['Sandbox'].replace({'VirusTotal Box of Apples': 'Box of Apples'})

    print(sandbox_df)
    # Extract years
    all_df[columnNameFirstSubmissionDate] = pd.to_datetime(all_df[columnNameFirstSubmissionDate])
    all_df['Year'] = all_df[columnNameFirstSubmissionDate].dt.year.astype(int)

    # Merge the sandbox data with the main DataFrame (match by Hash)
    all_df = all_df.merge(sandbox_df, on="Hash", how="inner")  # Use inner join to keep only matched records

    # Group by Year, Sandbox, and CPU_Type
    grouped_df = all_df.groupby(['Year', 'Sandbox', 'CPU_Type']).size().unstack(fill_value=0)
    
    # Drop 'w/o behavior'
    grouped_df = grouped_df.drop(columns=['w/o behavior'], errors='ignore')
    print(grouped_df)
    # Plotting: One stacked bar chart for each sandbox
    sandboxes = grouped_df.index.get_level_values('Sandbox').unique()

    plt.figure(figsize=(15, 10))

    for i, sandbox in enumerate(sandboxes):
        sandbox_data = grouped_df.xs(sandbox, level='Sandbox')  # Extract sandbox-specific data

        # **Remove CPU types that are all zero for this sandbox**
        sandbox_data = sandbox_data.loc[:, (sandbox_data != 0).any(axis=0)]

        ax = plt.subplot(len(sandboxes), 1, i + 1)
        sandbox_data.plot(kind='bar', stacked=True, ax=ax, cmap='tab20', alpha=0.7)

        ax.set_title(f"CPU Type Distribution for {sandbox}")
        ax.set_xlabel('Year')
        ax.set_ylabel('Number of Samples')
        ax.set_yscale('log')  # Log scale for y-axis
        ax.set_xticklabels(sandbox_data.index, rotation=45)

        # **Only include CPU types that exist in this specific sandbox**
        ax.legend(title='CPU Type', labels=sandbox_data.columns, loc='upper left', bbox_to_anchor=(1, 1), fontsize='small', frameon=True)

    plt.tight_layout()
    plt.savefig(os.path.join(save_path, "sandbox_cpu_type_distribution_log.pdf"))
    plt.close()




timeLineSandboxCPUTypeDistribution()
timeLineCPUSamplesWithPercentageWithoutBehaviorTWOBARSBUTSECONDFUNC()
