# Download the json for vulns you want to report on
# Place the json files and this script in a folder and run the script, it will parse all .json files in the folder
import json
import re
from tabulate import tabulate
from pprint import pprint
import os

# Helper function to remove the prefix
def get_suffix(arn):
    return arn[arn.rfind(':'):][1:]

def get_prefix(arn):
    return arn[:arn.rfind(':')]

def tabulate_in_overleaf_format(data):
    print(tabulate([("'"+x['name']+"'"," & '"+get_suffix(x['arn'])+"',") for x in data],headers=["'Name'", "& 'Arn'"]))
    print("Arn Prefix: {}/".format(get_prefix(data[0]['arn'])))

def parse_scout_file(filename):
    print("Parsing {}".format(filename))
    with open(filename) as f:
        data = json.load(f)
    tabulate_in_overleaf_format(data)
    print()

for file in [x for x in os.listdir() if x.endswith('.json')]:
    parse_scout_file(file)
