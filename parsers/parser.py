import xml.etree.ElementTree as ET
import pandas as pd
import json

class Parser:
    @staticmethod
    def get_nessus_df(nessus_file):
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

    @staticmethod
    def read_cklb(checklistB):
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

        df_cklb = pd.DataFrame.from_dict(result_dict, orient='index')

        status_mapping = {
            'not_a_finding': 'Not a Finding',
            'not_reviewed': 'Not Reviewed',
            'not_applicable': 'Not Applicable',
            'open': 'Open'
        }
        df_cklb.index = df_cklb.index.map(status_mapping)

        return df_cklb

    @staticmethod
    def read_checklist(checklist):
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

    #@staticmethod
    #def get_csv_values( dataframe, category):
    #    dataframe.index = dataframe.index.str.lower()
        #categoryFindingsOpen = dataframe.loc['Open', category] if 'Open' in status_severity_counts.index and category in status_severity_counts.columns else 0
    #    categoryFindingsOpen = dataframe.loc['open', category] if 'open' in dataframe.index and category in dataframe.columns else 0
    #    categoryFindingsClosed = dataframe.loc['not a finding', category] if 'not a finding' in dataframe.index and category in dataframe.columns else 0
    #    categoryFindingsNA = dataframe.loc['not applicable', category] if 'not applicable' in dataframe.index and category in dataframe.columns else 0
    #    categoryFindingsNotReviewed = dataframe.loc['not reviewed', category] if 'not reviewed' in dataframe.index and category in dataframe.columns else 0

    #    return categoryFindingsOpen, categoryFindingsClosed, categoryFindingsNA, categoryFindingsNotReviewed