import pandas as pd


class Csv:

    @staticmethod
    def get_csv_values( dataframe, category):
        dataframe.index = dataframe.index.str.lower()
        #categoryFindingsOpen = dataframe.loc['Open', category] if 'Open' in status_severity_counts.index and category in status_severity_counts.columns else 0
        categoryFindingsOpen = dataframe.loc['open', category] if 'open' in dataframe.index and category in dataframe.columns else 0
        categoryFindingsClosed = dataframe.loc['not a finding', category] if 'not a finding' in dataframe.index and category in dataframe.columns else 0
        categoryFindingsNA = dataframe.loc['not applicable', category] if 'not applicable' in dataframe.index and category in dataframe.columns else 0
        categoryFindingsNotReviewed = dataframe.loc['not reviewed', category] if 'not reviewed' in dataframe.index and category in dataframe.columns else 0

        return categoryFindingsOpen, categoryFindingsClosed, categoryFindingsNA, categoryFindingsNotReviewed