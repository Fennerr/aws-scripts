#!/usr/bin/env python3
import boto3
import argparse
import json
import logging
import pathlib


###################################################
# Input Variables
parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('optional named arguments')
requiredNamed.add_argument("-f","--file",type=str,help="The input file to perform analysis of",required=False)

optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("--env",type=str,help="Use Environment Variables rather than an AWS profile")
optionalNamed.add_argument("--region",type=str,help="To enumerate the policies for a specific region (defaults to all regions)")
optionalNamed.add_argument("--log",default='info',type=str,help="The logging level (debug,info,warning,error,critical)")

# Get the passed arguements
# args = parser.parse_args()


###################################################
# Helper functions

def read_data(filename):
    # Make output dir if it doesnt exist
    output_dir = pathlib.Path(__file__).parent.absolute() / 'output'
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    return json.loads(filepath.read_text())


roles = read_data('657031606740-iam_role_trust_policies.json')



# Check if the role trusts an AWS service to assume it
roles_service_can_assume_without_condition = []
roles_service_can_assume_with_a_condition = []
for role_name in roles.keys():
    role_data = roles[role_name]
    for statement in role_data.get('Statement'):
        if 'Service' in statement.get('Principal').keys(): 
            trusted_service = statement.get('Principal').get('Service')
            if type(trusted_service) == list:
                trusted_service = ', '.join(trusted_service)
            if 'Condition' in statement.keys():
                condition = statement.get('Condition')
                print(f"[+] {trusted_service} is allowed to assume {role_name} with a condition")
                print(condition)
                roles_service_can_assume_with_a_condition.append(role_name)
            else:
                print(f"[-] {trusted_service} is allowed to assume {role_name} without a condition")
                roles_service_can_assume_without_condition.append(role_name)



for role in roles_service_can_assume_without_condition:
    print(role)

