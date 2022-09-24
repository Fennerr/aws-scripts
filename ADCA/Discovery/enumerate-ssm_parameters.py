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
parser = argparse.ArgumentParser()
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use")
optionalNamed.add_argument("--env",type=str,help="Use Environment Variables rather than an AWS profile")
optionalNamed.add_argument("--region",type=str,help="To enumerate the policies for a specific region (defaults to all regions)")
optionalNamed.add_argument("--log",default='info',type=str,help="The logging level (debug,info,warning,error,critical)")


# Get the passed arguements
args = parser.parse_args()


def enumerate_ssm(s):
    regions = s.get_available_regions('ssm')
    for region in regions:
        logger.debug(f"Enumerating SSM parameters for {region}")
        try:
            ssm = s.client('ssm',region_name=region)
            parameters = []
            response = ssm.describe_parameters()
            parameters.extend(response['Parameters'])
            while 'NextToken' in response.keys():
                response = ssm.describe_parameters(NextToken = response['NextToken'])
                parameters.extend(response['Parameters'])
            logger.info(f"Found {len(parameters)} SSM parameters in {region}")
        except:
            logger.debug(f"Region {region} is not allowed")
    return parameters


def enumerate_vpc_flow_logs(s):
    regions = s.get_available_regions('ec2')
    for region in regions:
        logger.debug(f"Enumerating VPC FLow Logs for {region}")
        try:
            ec2 = s.client('ec2',region_name=region)
            flow_logs = []
            response = ec2.describe_flow_logs()
            flow_logs.extend(response['FlowLogs'])
            while 'NextToken' in response.keys():
                response = ec2.describe_flow_logs(NextToken = response['NextToken'])
                flow_logs.extend(response['FlowLogs'])
            logger.info(f"Found {len(flow_logs)} flow log configurations in {region}")
        except:
            logger.debug(f"Region {region} is not allowed")
    return flow_logs

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
# Create the boto session
if args.env:
    s = boto3.session.Session()
else:
    s = boto3.session.Session(profile_name=args.profile)

# Check that the profile creds are valid
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

# enumerate_ssm(s)
enumerate_vpc_flow_logs(s)

