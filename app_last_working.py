import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output
from dash_bootstrap_templates import load_figure_template
import dash_bootstrap_components as dbc
import plotly.express as px
import pandas as pd
import xml.etree.ElementTree as ET
import os
import glob
from pandas import json_normalize
from collections import Counter
import json
import pdb

directory_path = 'C:/Users/Robert.Rodriguez/Desktop/Roland/'
csv_files = glob.glob(os.path.join(directory_path, '*.csv'))
nessus_files = glob.glob(os.path.join(directory_path, '*.nessus'))
cklb_files = glob.glob(os.path.join(directory_path, '*.cklb'))
checklist_files = glob.glob(os.path.join(directory_path, '*.ckl'))
all_files = csv_files + nessus_files + cklb_files + checklist_files

totalOpen = totalClosed = totalNA = totalNotReviewed = 0
totalCriticalFindingsOpen = criticalFindingsOpen = totalHighFindingsOpen = totalMediumFindingsOpen = totalLowFindingsOpen = 0
totalHighFindingsClosed = totalMediumFindingsClosed = totalLowFindingsClosed = 0
totalHighFindingsNA = totalMediumFindingsNA = totalLowFindingsNA = 0
totalHighFindingsNotReviewed = totalMediumFindingsNotReviewed = totalLowFindingsNotReviewed = 0

def getCsvValues( dataframe, category):
    dataframe.index = dataframe.index.str.lower()
    #categoryFindingsOpen = dataframe.loc['Open', category] if 'Open' in status_severity_counts.index and category in status_severity_counts.columns else 0
    categoryFindingsOpen = dataframe.loc['open', category] if 'open' in dataframe.index and category in dataframe.columns else 0
    categoryFindingsClosed = dataframe.loc['not a finding', category] if 'not a finding' in dataframe.index and category in dataframe.columns else 0
    categoryFindingsNA = dataframe.loc['not applicable', category] if 'not applicable' in dataframe.index and category in dataframe.columns else 0
    categoryFindingsNotReviewed = dataframe.loc['not reviewed', category] if 'not reviewed' in dataframe.index and category in dataframe.columns else 0

    return categoryFindingsOpen, categoryFindingsClosed, categoryFindingsNA, categoryFindingsNotReviewed

def getNessusDf(nessus_file):
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    data = []
    for report in root.findall('Report'):
        for host in report.findall('ReportHost'):
            host_ip = host.find('HostProperties/tag[@name="host-ip"]').text if host.find('HostProperties/tag[@name="host-ip"]') is not None else 'N/A'
            for item in host.findall('ReportItem'):
                plugin_id = item.get('pluginID')
                severity = item.get('severity')
                port = item.get('port')
                protocol = item.get('protocol')
                description = item.find('description').text if item.find('description') is not None else 'N/A'
                solution = item.find('solution').text if item.find('solution') is not None else 'N/A'

                data.append({
                    'host_ip': host_ip,
                    'plugin_id': plugin_id,
                    'severity': severity,
                    'port': port,
                    'protocol': protocol,
                    'description': description,
                    'solution': solution
                })
    df = pd.DataFrame(data)
    return df

def readCKLB(checklistB):
    result_dict = {}

    with open(checklistB, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for i, rule in enumerate(data['stigs'][0]['rules']):
        severity = rule.get('severity')
        status = rule.get('status')
        if status not in result_dict:
            result_dict[status] = {'high': 0, 'medium': 0, 'low': 0}

        if severity in result_dict[status]:
            result_dict[status][severity] += 1

    df_CKLB = pd.DataFrame.from_dict(result_dict, orient='index')

    status_mapping = {
        'not_a_finding': 'Not a Finding',
        'not_reviewed': 'Not Reviewed',
        'not_applicable': 'Not Applicable',
        'open': 'Open'
    }
    df_CKLB.index = df_CKLB.index.map(status_mapping)

    return df_CKLB

def readChecklist(checklist):
    tree = ET.parse(checklist)
    root = tree.getroot()
    data = []

    for vuln in root.findall('.//VULN'):
        sevrity_element = vuln.find('.//STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').text

        status_element = vuln.find('.//STATUS').text


        data.append({
            'severity' : sevrity_element,
            'status' : status_element
        })

    df_CKL = pd.DataFrame(data)
    severity_status_counts = pd.crosstab(df_CKL['status'], df_CKL['severity'], margins=False, dropna=False)

    status_mapping = {
        'NotAFinding': 'Not a Finding',
        'Not_Reviewed': 'Not Reviewed',
        'Not_Applicable': 'Not Applicable',
        'Open': 'Open'
    }
    severity_status_counts.index = severity_status_counts.index.map(status_mapping)

    return severity_status_counts


for file in all_files:
    #breakpoint()
    print(file)
    if ".nessus" in file:
        #print("i have a nessus file")
        nessus_df = getNessusDf(file)
        severity_counts = nessus_df['severity'].value_counts()
        criticalFindingsOpen = severity_counts.get('4', 0)
        highFindingsOpen = severity_counts.get('3', 0)
        mediumFindingsOpen = severity_counts.get('2', 0)
        lowFindingsOpen = severity_counts.get('1', 0)

        highFindingsClosed = mediumFindingsClosed = lowFindingsClosed = 0
        highFindingsNA = mediumFindingsNA = lowFindingsNA = 0
        highFindingsNotReviewed = mediumFindingsNotReviewed = lowFindingsNotReviewed = 0
        #print(f" nessus results for lowFindingsOpen: {criticalFindingsOpen}")

    if ".cklb" in file:
        #print("I have a cklb file")
        status_severity_counts = readCKLB(file)

        highFindingsOpen, highFindingsClosed, highFindingsNA, highFindingsNotReviewed = getCsvValues(status_severity_counts,'high')
        mediumFindingsOpen, mediumFindingsClosed, mediumFindingsNA, mediumFindingsNotReviewed = getCsvValues(status_severity_counts,'medium')
        lowFindingsOpen, lowFindingsClosed, lowFindingsNA, lowFindingsNotReviewed = getCsvValues(status_severity_counts,'low')

        #print(file)
        #print(f"Rob here is what you want highOpen {highFindingsOpen}, mediumOpen {mediumFindingsOpen}, lowOpen {lowFindingsOpen}/\
        #      highClosed {highFindingsClosed}, mediumClosed {mediumFindingsClosed}, lowClosed {lowFindingsClosed}/\
        #      highNA {highFindingsNA}, mediumNA {mediumFindingsNA}, lowNA {lowFindingsNA}/\
        #      highNR {highFindingsNotReviewed}, mediumNR {mediumFindingsNotReviewed}, lowNR {lowFindingsNotReviewed}")

    if ".ckl" in file and ".cklb" not in file:
        status_severity_counts = readChecklist(file)

        highFindingsOpen, highFindingsClosed, highFindingsNA, highFindingsNotReviewed = getCsvValues(status_severity_counts,'high')
        mediumFindingsOpen, mediumFindingsClosed, mediumFindingsNA, mediumFindingsNotReviewed = getCsvValues(status_severity_counts,'medium')
        lowFindingsOpen, lowFindingsClosed, lowFindingsNA, lowFindingsNotReviewed = getCsvValues(status_severity_counts,'low')     

        #print(file)
        #print(f"Rob here is what you want highOpen {highFindingsOpen}, mediumOpen {mediumFindingsOpen}, lowOpen {lowFindingsOpen}/\
        #      highClosed {highFindingsClosed}, mediumClosed {mediumFindingsClosed}, lowClosed {lowFindingsClosed}/\
        #      highNA {highFindingsNA}, mediumNA {mediumFindingsNA}, lowNA {lowFindingsNA}/\
        #      highNR {highFindingsNotReviewed}, mediumNR {mediumFindingsNotReviewed}, lowNR {lowFindingsNotReviewed}")   


    if ".csv" in file:
        #print("I have a csv")
        df = pd.read_csv(file, skiprows=1)
        status_severity_counts = df.groupby(['Status', 'Severity']).size().unstack(fill_value=0)  
        #print(f"{status_severity_counts} ok done")

        highFindingsOpen, highFindingsClosed, highFindingsNA, highFindingsNotReviewed = getCsvValues(status_severity_counts,'high')
        mediumFindingsOpen, mediumFindingsClosed, mediumFindingsNA, mediumFindingsNotReviewed = getCsvValues(status_severity_counts,'medium')
        lowFindingsOpen, lowFindingsClosed, lowFindingsNA, lowFindingsNotReviewed = getCsvValues(status_severity_counts,'low')
        
        #print(file)
        #print(f"Rob here is what you want highOpen {highFindingsOpen}, mediumOpen {mediumFindingsOpen}, lowOpen {lowFindingsOpen}/\
        #      highClosed {highFindingsClosed}, mediumClosed {mediumFindingsClosed}, lowClosed {lowFindingsClosed}/\
        #      highNA {highFindingsNA}, mediumNA {mediumFindingsNA}, lowNA {lowFindingsNA}/\
        #      highNR {highFindingsNotReviewed}, mediumNR {mediumFindingsNotReviewed}, lowNR {lowFindingsNotReviewed}")

    #breakpoint()
    stigSumOfOpen = criticalFindingsOpen + highFindingsOpen + mediumFindingsOpen + lowFindingsOpen
    stigSumOfClosed = highFindingsClosed + mediumFindingsClosed + lowFindingsClosed
    stigSumOfNA = highFindingsNA + mediumFindingsNA + lowFindingsNA
    stigSumOfNotReviewed = highFindingsNotReviewed + mediumFindingsNotReviewed + lowFindingsNotReviewed

    #breakpoint()

    totalOpen += stigSumOfOpen
    totalClosed += stigSumOfClosed
    totalNA += stigSumOfNA
    totalNotReviewed += stigSumOfNotReviewed

    #breakpoint()

    totalCriticalFindingsOpen += criticalFindingsOpen
    totalHighFindingsOpen += highFindingsOpen
    totalMediumFindingsOpen += mediumFindingsOpen
    totalLowFindingsOpen += lowFindingsOpen

    totalHighFindingsClosed += highFindingsClosed
    totalMediumFindingsClosed += mediumFindingsClosed
    totalLowFindingsClosed += lowFindingsClosed

    totalHighFindingsNA += highFindingsNA
    totalMediumFindingsNA += mediumFindingsNA
    totalLowFindingsNA += lowFindingsNA

    totalHighFindingsNotReviewed += highFindingsNotReviewed
    totalMediumFindingsNotReviewed += mediumFindingsNotReviewed
    totalLowFindingsNotReviewed += lowFindingsNotReviewed
    #breakpoint()

    criticalFindingsOpen = 0


    #print(f"These are the totals for: Closed: {stigSumOfClosed}, Open: {stigSumOfOpen}, NA: {stigSumOfNA}, Not Reviewed: {stigSumOfNotReviewed}")

print(f"{totalCriticalFindingsOpen}, {totalHighFindingsOpen}, {totalMediumFindingsOpen}, {totalLowFindingsOpen}, = {totalOpen} <- Open ")
print(f"{totalHighFindingsClosed}, {totalMediumFindingsClosed}, {totalLowFindingsClosed}, = {totalClosed} <- Closed ")
print(f"{totalHighFindingsNA}, {totalMediumFindingsNA}, {totalLowFindingsNA}, = {totalNA} <- NA ")
print(f"{totalHighFindingsNotReviewed}, {totalMediumFindingsNotReviewed}, {totalLowFindingsNotReviewed}, = {totalNotReviewed} <- Not Reviewed ")

#  ******************************************* PICK UP HERE**************************************

status_counts = {
    "Cat1's Open" : totalHighFindingsOpen + totalCriticalFindingsOpen,
    "Cat2's Open" : totalMediumFindingsOpen,
    "Cat3's Open" : totalLowFindingsOpen,
    "Cat1's Closed" : totalHighFindingsClosed,
    "Cat2's Closed" : totalMediumFindingsClosed,
    "Cat3's Closed" : totalLowFindingsClosed,
    "Cat1's NA" : totalHighFindingsNA,
    "Cat2's NA" : totalMediumFindingsNA,
    "Cat3's NA" : totalLowFindingsNA,
    "Cat1's Not Reviewed" : totalHighFindingsNotReviewed,
    "Cat2's Not Reviewed" : totalMediumFindingsNotReviewed,
    "Cat3's Not Reviewed" : totalLowFindingsNotReviewed
}

status_df = pd.DataFrame(list(status_counts.items()), columns=['Status & Severity', 'Count'])

#print(status_df)

# Pie chart for total status (Open, Closed, NA, Not Reviewed)
status_pie_df = pd.DataFrame({
    'Status': ['Open', 'Closed', 'NA', 'Not Reviewed'],
    'Count': [totalOpen, totalClosed, totalNA, totalNotReviewed]
})

# Pie chart for severity-specific counts (High, Medium, Low for Open, Closed, NA, Not Reviewed)
severity_pie_df_open = pd.DataFrame({
    'Severity': ["Cat1's Open", "Cat2's Open", "Cat3's Open"],
    'Count': [totalHighFindingsOpen + totalCriticalFindingsOpen, totalMediumFindingsOpen, totalLowFindingsOpen]
})

severity_pie_df_closed = pd.DataFrame({
    'Severity': ["Cat1's Closed", "Cat2's Closed", "Cat3's Closed"],
    'Count': [totalHighFindingsClosed, totalMediumFindingsClosed, totalLowFindingsClosed]
})

severity_pie_df_na = pd.DataFrame({
    'Severity': ["Cat1's NA", "Cat2's NA", "Cat3's NA"],
    'Count': [totalHighFindingsNA, totalMediumFindingsNA, totalLowFindingsNA]
})

severity_pie_df_not_reviewed = pd.DataFrame({
    'Severity': ["Cat1's Not Reviewed", "Cat2's Not Reviewed", "Cat3's Not Reviewed"],
    'Count': [totalHighFindingsNotReviewed, totalMediumFindingsNotReviewed, totalLowFindingsNotReviewed]
})

#fig = px.pie(status_df, names='Status & Severity', values='Count', title='Findings by Severity and Status')

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
load_figure_template('DARKLY')

app.layout = html.Div([
    html.Div([
        html.Div([
            html.H3("Assessment Status", style={"margin-bottom": "0px", 'color': 'white', 'textAlign': 'center'}),
            html.H5('Track Control Stig Statuses', style={"margin-top": "0px", 'color': 'white'}),
        ], className="one-half column", id="title",
        style={'textAlighn': 'center'}),
    ], id="header", className="row flex-display", style={"margin-bottom": "25px",
                                                         "display": "flex",
                                                         "justifyContent": "center",
                                                         "alignItems": "center"}),

    html.Div([
        html.Div([
            html.H6(children='Total Open Controls',
                    style={
                        'textAlign': 'center',
                        'color': 'white'}
                    ),

    html.P(f"{totalOpen}",
                   style={
                       'textAlign': 'center',
                       'color': '#dd1e35',
                       'fontSize': 40}
                   )], className="card_container three columns",
        ),

    html.Div([
            html.H6(children='Total Controls Not Reviewed',
                    style={
                        'textAlign': 'center',
                        'color': 'white'}
                    ),

            html.P(f"{totalNotReviewed}",
                   style={
                       'textAlign': 'center',
                       'color': '',
                       'fontSize': 40}
                   )], className="card_container three columns",
                   style={'color': 'green'},
    ),

    html.Div([
            html.H6(children="Total Cat1's Open",
                    style={
                        'textAlign': 'center',
                        'color': 'white'}
                    ),

            html.P(f"{totalHighFindingsOpen + totalCriticalFindingsOpen}",
                   style={
                       'textAlign': 'center',
                       'color': '#e55467',
                       'fontSize': 40}
                   )], className="card_container three columns",
    ),

    html.Div([
            html.H6(children="Total Cat1's Not Reviewed",
                    style={
                        'textAlign': 'center',
                        'color': 'white'}
                    ),

            html.P(f"{totalHighFindingsNotReviewed}",
                   style={
                       'textAlign': 'center',
                       'color': 'green',
                       'fontSize': 40}
                   )], className= "card_container three columns")
    ], className= "row flex-display"),

    html.Div([
        html.Div([
            html.P('Select Stig Scenario:', className= 'fix_label', style={'color': 'white'}),

            dcc.Dropdown(id='chart-dropdown',
                         options=[{'label': 'All Controls', 'value': 'status'},
                                  {'label': 'Open Findings by Severity', 'value': 'open'},
                                  {'label': 'Closed Findings by Severity', 'value': 'closed'},
                                  {'label': 'N/A Findings by Severity', 'value': 'na'},
                                  {'label': 'Not Reviewed Findings by Severity', 'value': 'not_reviewed'}
                                  ], className= 'dcc_compon',
                        value='status',  # default value
                        style={'color': 'black'}),     

            html.P('Select to See Values in Percentage or Actual Numbers:', className= 'fix_label_small', style={'color': 'white'}),
                   
            # Toggle to select between percentage and actual numbers
            dcc.RadioItems(
                id='percentage-toggle',
                options=[
                    {'label': 'Percentage', 'value': 'percentage'},
                    {'label': 'Actual Numbers', 'value': 'actual'}
                ], className= 'dcc_compon',
                value='actual',  # default value
                labelStyle={'display': 'inline-block'},
                style={'margin-top': '20px', 'color': 'white'},
            ),
            ], className="create_container three columns", id="cross-filter-options"),

                html.Div([
                    dcc.Graph(id='example-pie-chart'),
                ], className="create_container four columns"),
                ], className="row flex-display"),
    ],id="mainContainer",
    style={"display": "flex", "flex-direction": "column"})


# Callback to update the pie chart based on dropdown selection
@app.callback(
    Output('example-pie-chart', 'figure'),
    [Input('chart-dropdown', 'value'),
     Input('percentage-toggle', 'value')]
)
def update_pie_chart(selected_value, toggle_value):
    # Set the textinfo based on the toggle (percentage or actual numbers)
    if toggle_value == 'percentage':
        textinformation = 'percent'
    else:
        textinformation = 'value'


    if selected_value == 'status':
        fig = px.pie(status_pie_df, names='Status', values='Count', title='Status of All controls')
    elif selected_value == 'open':
        fig = px.pie(severity_pie_df_open, names='Severity', values='Count', title='Open Findings by Severity')
    elif selected_value == 'closed':
        fig = px.pie(severity_pie_df_closed, names='Severity', values='Count', title='Closed Findings by Severity')
    elif selected_value == 'na':
        fig = px.pie(severity_pie_df_na, names='Severity', values='Count', title='Not Applicable Findings by Severity')
    elif selected_value == 'not_reviewed':
        fig = px.pie(severity_pie_df_not_reviewed, names='Severity', values='Count', title='Not Reviewed Findings by Severity')
    fig.update_traces(textinfo= textinformation)
    #fig.update_layout(margin=dict(t=0, b=0, l=500, r=0))
    fig.update_layout(autosize=True)
    return fig

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
