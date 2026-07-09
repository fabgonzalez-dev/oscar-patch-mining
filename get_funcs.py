import csv
from pathlib import Path
import ast

f1 = Path('evaluation/precision_validation_samples.csv')
f2 = Path('evaluation/precision_validation_samples_extra.csv')

def get_vulns(filepath):
    res = set()
    with open(filepath, 'r') as f:
        for row in csv.DictReader(f):
            res.add(row['vuln_id'])
    return res

v = get_vulns(f1)
v.update(get_vulns(f2))

funcs = 0
for data_file in ['data/ghsa_npm_extraction.csv', 'data/ghsa_pypi_extraction.csv']:
    with open(data_file, 'r') as f:
        for row in csv.DictReader(f):
            if row['vuln_id'] in v:
                extracted = row.get('functions_extracted', '')
                if extracted:
                    try:
                        lst = ast.literal_eval(extracted)
                        funcs += len(lst)
                    except:
                        pass
print(f'Total functions extracted from the 92 advisories: {funcs}')
