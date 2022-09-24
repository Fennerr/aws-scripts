#!/usr/bin/env python3
import boto3
import argparse
import json
import logging
import pathlib
###################################################
# Input Variables
parser = argparse.ArgumentParser()
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use")
optionalNamed.add_argument("--env",type=str,help="Use Environment Variables rather than an AWS profile")
optionalNamed.add_argument("--region",type=str,help="To enumerate the policies for a specific region (defaults to all regions)")
optionalNamed.add_argument("--log",default='info',type=str,help="The logging level (debug,info,warning,error,critical)")

# Get the passed arguements
args = parser.parse_args()


###################################################
# Helper functions

def find_not_allowed_regions():
    # Want to determine which regions are not allowed according to SCPs
    # Cant use global service to do this test, such as iam/sts/s3 etc
    # https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html#example-scp-deny-region
    # Will use sqs.list_queues for now, but that assume that the calling principal has the permission to perform this action (before SCPs deny it)
    regions = s.get_available_regions('sqs')
    not_allowed_regions = []
    for region in regions:
        try:
            sqs = s.client('sqs',region_name=region)
            sqs.list_queues()
            logger.debug(f"Region {region} is allowed")
        except:
            not_allowed_regions.append(region)
            logger.debug(f"Region {region} is not allowed")
    return not_allowed_regions

def write_output(filename,results):
    with open(filename, 'w') as outputfile:
        ## Need to make indentation an option
        json.dump(results, outputfile, indent=4)

def save_data(filename,data):
    # Make output dir if it doesnt exist
    output_dir = pathlib.Path(__file__).parent.absolute() / 'output'
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    with filepath.open("w") as write_file:
        json.dump(data, write_file, indent=4, default=str)


###################################################
# Service functions

def get_secretsmanager_secret_values(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('secretsmanager')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    
    secret_values = []

    for region in regions:
        logger.debug(f"Enumerating ECS Task Difinitions for {region}")
        secretsmanager = s.client('secretsmanager',region_name=region)
        secrets_list = []
        try:
            response = secretsmanager.list_secrets()
            secrets_list.extend(response['SecretList'])
            while 'nextToken' in response.keys():
                response = secrets_list.list_secrets(nextToken = response['nextToken'])
                secrets_list.extend(response['taskDefinitionArns'])
        except secretsmanager.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue

        if not secrets_list:
            logger.info(f"No Secrets Manager secrets in {region}")
            continue

        logger.info(f"Found {len(secrets_list)} secrets in {region}")

        for secret in secrets_list:
            secret_value = secretsmanager.get_secret_value(SecretId=secret['ARN'])['SecretString']
            try:
                data = {
                    'Secret ARN': secret['ARN'],
                    'Region': region,
                    'Value': secret_value
                }
                secret_values.append(data)
                logger.debug(data)
            except secretsmanager.exceptions.ResourceNotFoundException:
                continue
    save_data(f"{account_id}-secretsmanager-secret_values.json",secret_values)



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
    # You can modify what the logger's messages look like here
    FORMATS = {
        logging.DEBUG: f"{grey}{level}{reset} - {message}",
        logging.INFO: f"{grey}{level}{reset} - {message}",
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

# Create the boto session
if args.env:
    s = boto3.session.Session()
else:
    s = boto3.session.Session(profile_name=args.profile)


# Check that the profile creds are valid
sts = s.client('sts')
try:
    sts_info = sts.get_caller_identity()
    account_id = sts_info.get('Account')
    logger.info(f"Using profile {args.profile} in account {account_id} with ARN {sts_info.get('Arn')}")
except sts.exceptions.ClientError as e:
    logger.critical(f"{e}")
    logger.critical(f"Exiting..")
    exit()

# Get a list of regions blocked by the SCP to reduce the errors thrown when enumerating the resource-policies across all regions
if not args.region:
    logger.debug("Determining which regions are not allowed")
    not_allowed_regions = find_not_allowed_regions()
    if not_allowed_regions:
        logger.debug(f"Not allowed regions: {not_allowed_regions}")
    else:
        logger.debug("All regions are allowed")

# get_lambda_policies(specific_region=args.region)
# get_sqs_access_policies(specific_region=args.region)
# get_cloudwatch_log_policies(specific_region=args.region)
# get_ecr_repository_policies(specific_region=args.region)
# get_iam_role_trust_policies(specific_region=args.region)
# get_guardduty_detector_configurations(specific_region=args.region)
get_secretsmanager_secret_values(specific_region=args.region)