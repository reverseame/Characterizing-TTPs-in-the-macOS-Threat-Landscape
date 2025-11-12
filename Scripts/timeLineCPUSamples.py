
import subprocess
import pandas as pd
import os
import matplotlib.pyplot as plt
from matplotlib import rc
import matplotlib.ticker as ticker

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



output_dir = '../Output/Hashes_info/VT_JSON'
save_path = '../Output/Graphics/'

columnNameFirstSubmissionDate = "first_submission_date" 
columnNameHash = "Hash"
columnNameCount = "Count"
columnNameCpu = "cpu_type"

def time_line_cpu_year_distribution():
    """
    Plot CPU type distribution over years with and without behavior samples.

    Loads merged CSVs, assigns "Without behavior" for unknown samples, aggregates by year,
    and generates a stacked bar chart comparing CPU types and unknown samples.
    """
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    print(len(all_df))
    all_hashes_with_info = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')
    print(len(all_hashes_with_info))
    known_hashes = set(all_hashes_with_info[columnNameHash])
    all_df['CPU_Type'] = all_df[columnNameHash].apply(lambda h: 'Without behavior' if h not in known_hashes else None)     # Identify "w/o behavior" (previously "Unknown") hashes
    all_df.loc[all_df['CPU_Type'].isna(), 'CPU_Type'] = all_df[columnNameCpu]

    all_df = all_df.dropna(subset=['CPU_Type'])
    all_df['CPU_Type'] = all_df['CPU_Type'].astype(str).str.strip()
    all_df = all_df[all_df['CPU_Type'] != ""]

    all_df[columnNameFirstSubmissionDate] = pd.to_datetime(all_df[columnNameFirstSubmissionDate])
    all_df['Year'] = all_df[columnNameFirstSubmissionDate].dt.year

    grouped_df = all_df.groupby(['Year', 'CPU_Type']).size().reset_index(name='count')
    counts = grouped_df.groupby('CPU_Type')['count'].sum()
    sorted_cpu_types = counts.sort_values(ascending=False).index.tolist()

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

    
    pivot_df = all_df.groupby(['Year', 'CPU_Type']).size().unstack(fill_value=0) # Pivot table for stacking
    all_years = list(range(all_df['Year'].min(), all_df['Year'].max() + 1))
    pivot_df = pivot_df.reindex(all_years, fill_value=0)

    
    wo_behavior_df = pivot_df['Without behavior'] if 'Without behavior' in pivot_df.columns else pd.Series(0, index=pivot_df.index)
    pivot_df = pivot_df.drop(columns=['Without behavior'], errors='ignore')


    fig, ax = plt.subplots(figsize=(13, 7))
    pivot_df.plot(kind='bar', stacked=True, ax=ax, width=0.4, color=cpu_colors, alpha=0.7, position=1)
    wo_behavior_df.plot(kind='bar', ax=ax, width=0.4, color='#B0B0B0', alpha=0.7, position=0)

    ax.set_yscale('symlog', linthresh=1)
    y_max = max(pivot_df.sum(axis=1).max(), wo_behavior_df.max())
    ax.set_ylim(1, y_max)

    ax.yaxis.set_major_locator(ticker.LogLocator(base=10.0))
    ax.yaxis.set_minor_locator(ticker.LogLocator(base=10.0, subs='auto', numticks=100))
    ax.yaxis.set_minor_formatter(ticker.NullFormatter())

    ax.grid(False)

    for label in ax.get_yticklabels():
        if label.get_text() in ['1', '10⁰', r'$10^0$']:
            label.set_verticalalignment('bottom')  
            label.set_y(0.05)  


    ax.set_xlabel('Year')
    ax.set_ylabel('Number of Samples')
    ax.set_xticks(range(len(all_years)))
    ax.set_xticklabels(all_years, rotation=45)

    handles, labels = ax.get_legend_handles_labels()
    sorted_labels = [label for label in sorted_cpu_types]
    sorted_handles = [handles[labels.index(label)] for label in sorted_cpu_types]

    ax.legend(
    sorted_handles, sorted_labels, title='CPU Type', loc='upper left',
    bbox_to_anchor=(0, 1.02), fontsize='x-small', frameon=True, ncol=2, borderaxespad=0.2
)


    plt.tight_layout()
    output_path = os.path.join(save_path, "timeLineCPUSamplesWithPercentage.pdf")
    plt.savefig(output_path)
    plt.close()
    cropped_output_path = os.path.join(save_path, "timeLineCPUAndBehTwoColum.pdf")
    subprocess.run(["pdfcrop", output_path, cropped_output_path])
    os.remove(output_path)


def time_line_sandbox_cpu_type_distribution():
    """
    Plot CPU type distribution per sandbox over years.

    Merges sandbox CSV with main data, filters sandboxes of interest, aggregates by Year/CPU,
    and plots stacked bar charts (log scale) for each sandbox.
    """
    all_df = pd.read_csv('../Output/csv/src/all_df_merged.csv')
    all_hashes_with_info = pd.read_csv('../Output/csv/unique_hashes_with_info.csv')
    sandbox_df = pd.read_csv('../Output/csv/src/sandbox_df.csv')  # Sandbox data

    known_hashes = set(all_hashes_with_info[columnNameHash])
    all_df['CPU_Type'] = all_df[columnNameHash].apply(lambda h: 'w/o behavior' if h not in known_hashes else None)

    all_df.loc[all_df['CPU_Type'].isna(), 'CPU_Type'] = all_df[columnNameCpu].str.strip()

    desired_sandboxes = ['VirusTotal Box of Apples', 'OS X Sandbox', 'Zenbox macOS']
    sandbox_df = sandbox_df[sandbox_df['Sandbox'].isin(desired_sandboxes)]
    sandbox_df['Sandbox'] = sandbox_df['Sandbox'].replace({'VirusTotal Box of Apples': 'Box of Apples'})

    all_df[columnNameFirstSubmissionDate] = pd.to_datetime(all_df[columnNameFirstSubmissionDate])
    all_df['Year'] = all_df[columnNameFirstSubmissionDate].dt.year.astype(int)

    all_df = all_df.merge(sandbox_df, on="Hash", how="inner")  # Use inner join to keep only matched records

    grouped_df = all_df.groupby(['Year', 'Sandbox', 'CPU_Type']).size().unstack(fill_value=0)
    grouped_df = grouped_df.drop(columns=['w/o behavior'], errors='ignore')
    sandboxes = grouped_df.index.get_level_values('Sandbox').unique()

    plt.figure(figsize=(15, 10))

    for i, sandbox in enumerate(sandboxes):
        sandbox_data = grouped_df.xs(sandbox, level='Sandbox')  # Extract sandbox-specific data

        sandbox_data = sandbox_data.loc[:, (sandbox_data != 0).any(axis=0)]

        ax = plt.subplot(len(sandboxes), 1, i + 1)
        sandbox_data.plot(kind='bar', stacked=True, ax=ax, cmap='tab20', alpha=0.7)

        ax.set_title(f"CPU Type Distribution for {sandbox}")
        ax.set_xlabel('Year')
        ax.set_ylabel('Number of Samples')
        ax.set_yscale('log') 
        ax.set_xticklabels(sandbox_data.index, rotation=45)

        ax.legend(title='CPU Type', labels=sandbox_data.columns, loc='upper left', bbox_to_anchor=(1, 1), fontsize='small', frameon=True)

    plt.tight_layout()
    plt.savefig(os.path.join(save_path, "sandbox_cpu_type_distribution_log.pdf"))
    plt.close()




time_line_sandbox_cpu_type_distribution()
time_line_cpu_year_distribution()