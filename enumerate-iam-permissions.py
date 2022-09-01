#!/usr/bin/env python3
import boto3
import argparse
import json
import logging
from termcolor import colored
sep = '------------------------------------------------------------------------'

###################################################3 
# Input Variables
parser = argparse.ArgumentParser()
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use")
optionalNamed.add_argument("--region",default='af-south-1',type=str,help="The default region to use (defaults to af-south-1)")
optionalNamed.add_argument("--log",default='warning',type=str,help="The logging level (debug,info,warning,error,critical)")

optionalNamed = parser.add_argument_group('To check a specific user or role')
optionalNamed.add_argument("--user",type=str,help="The user name to check")
optionalNamed.add_argument("--role",type=str,help="The role name to check")

# Get the passed arguements
args = parser.parse_args()

###################################################
# Setup Logging
numeric_level = getattr(logging, args.log.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % args.log)

class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    date = "%(asctime)s"
    level = "%(levelname)s"
    message = "%(message)s"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: f"{grey}{level}{reset} - {message}",
        logging.INFO: f"{message}",
        logging.WARNING: f"{yellow}{level}{reset} - {message}",
        logging.ERROR: f"{red}{level}{reset} - {message}",
        logging.CRITICAL: f"{bold_red}{level}{reset} - {message}",
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Use a logger (dont use logging.BasicConfig as boto also uses logging, and configuring it at the global level will make boto logs flood the stdout - need to use a logger specific to this script)
logger = logging.getLogger(__name__)
logger.setLevel(numeric_level)
# Need to configure a streamhandler to print to stdout
ch = logging.StreamHandler()
logger.addHandler(ch)
ch.setFormatter(CustomFormatter())

###################################################
# Actual logic
# Check that the creds are valid + get account ID and the calling principal ARN
s = boto3.session.Session(profile_name=args.profile)
sts = s.client('sts')
try:
    sts_info = sts.get_caller_identity()
except sts.exceptions.ClientError as e:
    logger.critical(f"{e}")
    logger.critical(f"Exiting..")
    exit()

current_arn = sts_info.get('Arn')
account_id = sts_info.get('Account')
print(f"Account Number: {account_id}")

# Setup the principal dict
principal = {}
if not (args.user or args.role):
    if 'assumed-role' in current_arn:
        principal['type'] = 'Role'
        principal['name'] = current_arn.split('/')[-2]
    else:
        principal['type'] = 'User'
        principal['name'] = current_arn.split('/')[-1]
elif args.user:
    principal['type'] = 'User'
    principal['name'] =  args.user
elif args.role:
    principal['type'] = 'Role'
    principal['name'] =  args.role

print(f"IAM {principal['type']} Name: {principal['name'] }")

###################################################
# Check for permissions for the principal
iam = s.client('iam')

# Group logic
if principal['type'] == 'User':
    print(sep)
    logger.info("Enumerating IAM Groups...")
    # Enumerate group memberships, and thier policies
    try:
        groups = iam.list_groups_for_user(UserName=principal['name'])['Groups']
    except iam.exceptions.ClientError as e:
        logger.critical(f"{e}")
        logger.critical(f"Cannot determine group membership, exiting...")
        exit()

    if not groups:
        logger.info(f"{colored('[*]','red')} User has no group associations")
    else:
        total_groups = len(groups)
        print(f"Found {colored(total_groups, 'blue')} group(s) associated with {principal['name']}")
        for count, group in enumerate(groups,1):
            print(f'{colored(f"[{count}/{total_groups}]","blue")} Enumerating group {group["GroupName"]}')

            # Check for an inline policy
            inline_policies = iam.list_group_policies(GroupName=group['GroupName'])['PolicyNames']
            if inline_policies:
                total_inline_policies = len(inline_policies)
                print(f"Found {colored(total_inline_policies, 'green')} in-line group policies")
                for count2,policy in enumerate(inline_policies,1):
                    print(f'{colored(f"[{count2}/{total_inline_policies}]","green")} Enumerating in-line policy {policy["PolicyName"]}')
                    inline_policy = iam.get_group_policy(GroupName=group['GroupName'],PolicyName=policy["PolicyName"])

            # Check for attached policies
            attached_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
            if attached_policies:
                total_attached_policies = len(attached_policies)
                print(f"Found {colored(total_attached_policies, 'green')} attached policies")
                for count2,policy in enumerate(attached_policies,1):
                    print(f'{colored(f"[{count2}/{total_attached_policies}]","green")} Attached policy: {policy["PolicyName"]}')
                    # Dont print out policy documents for managed policies, unless log level is set to info or debug
                    if 'arn:aws:iam::aws:policy' in policy['PolicyArn'] and numeric_level >= 20:
                        print("%s is an AWS Managed Policy. Set log level to info or debug to display the policy document" % policy['PolicyArn'].split('/')[-1])
                        continue
                    attached_policy = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
                    default_policy_version = attached_policy['DefaultVersionId']
                    policy_document = iam.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=default_policy_version)['PolicyVersion']['Document']
                    print(json.dumps(policy_document,indent=4))
                    pass

###################################################
# Enumerate Inline Policies
print(sep)
logger.info("Enumerating in-line policies...")
if principal['type'] == 'User':
    inline_policies = iam.list_user_policies(UserName=principal['name'])['PolicyNames']
else:
    inline_policies = iam.list_role_policies(RoleName=principal['name'])['PolicyNames']

if not inline_policies:
    logger.info(f"{colored('[*]','red')} {principal['type']} has no in-line policies")
else:
    total_inline_policies = len(inline_policies)
    print(f"Found {colored(total_inline_policies, 'green')} in-line policies")
    for count,policy in enumerate(inline_policies,1):
        print(f'{colored(f"[{count}/{total_inline_policies}]","green")} Retrieving in-line policy: {policy}')
        if principal['type'] == 'User':
            policy_document = iam.get_user_policy(UserName=principal['name'],PolicyName=policy)['PolicyDocument']
        else:
            policy_document = iam.get_role_policy(RoleName=principal['name'],PolicyName=policy)['PolicyDocument']
        print(json.dumps(policy_document,indent=4))

###################################################
# Enumerate Attached Policies
print(sep)
logger.info("Enumerating attached policies...")
if principal['type'] == 'User':
    attached_policies = iam.list_attached_user_policies(UserName=principal['name'])['AttachedPolicies']
else:
    attached_policies = iam.list_attached_role_policies(RoleName=principal['name'])['AttachedPolicies']

if not attached_policies:
    logger.info(f"{colored('[*]','red')} {principal['type']} has no attached policies")
else:
    print(sep)
    total_attached_policies = len(attached_policies)
    print(f"Found {colored(total_attached_policies, 'green')} attached policies")
    for count,policy in enumerate(attached_policies,1):
        print(f'{colored(f"[{count}/{total_attached_policies}]","green")} Retrieving attached policy: {policy["PolicyName"]}')
        # Dont print out policy documents for managed policies, unless log level is set to info or debug
        if 'arn:aws:iam::aws:policy' in policy['PolicyArn'] and numeric_level >= 20:
            print("%s is an AWS Managed Policy. Set log level to info or debug to display the policy document" % policy['PolicyArn'].split('/')[-1])
            continue
        attached_policy = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
        default_policy_version = attached_policy['DefaultVersionId']
        policy_document = iam.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=default_policy_version)['PolicyVersion']['Document']
        print(json.dumps(policy_document,indent=4))