#!/usr/bin/env python3
import boto3
import argparse
import json
import logging

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
        json.dump(results, outputfile)


###################################################
# Service functions

def get_cloudwatch_log_policies(specific_region):
    # Cloudwatch Log policies can be used to allow cross-account access to subscribe to a log group
    if specific_region == None:
        regions = s.get_available_regions('logs')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    policies = []

    for region in regions:
        logs = s.client('logs',region_name=region)
        data = {
            'Region': region,
            'Policies': logs.describe_resource_policies().get('resourcePolicies')
        }
        policies.append(data)
        logger.debug(json.dumps(data))
    write_output(f"{account_id}-cloudwatch_log_policies.json",policies)
         

def get_lambda_policies(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('lambda')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    policies = []

    for region in regions:
        lc = s.client('lambda',region_name=region)
        try:
            lambda_functions = lc.list_functions()["Functions"]
        except lc.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue
        
        if not lambda_functions:
            logger.info(f"No lambda functions in {region}")
            continue

        logger.info(f"Found {len(lambda_functions)} lambda functions in {region}")

        for lambda_function in lambda_functions:
            function_name = lambda_function.get("FunctionName")
            try:
                data = {
                    'Function Name': function_name,
                    'Region': region,
                    'Policy': json.loads(lc.get_policy(FunctionName=lambda_function.get("FunctionName")).get('Policy'))
                }
                policies.append(data)
                logger.debug(json.dumps(data))
            except lc.exceptions.ResourceNotFoundException:
                continue
    write_output(f"{account_id}-lambda_policies.json",policies)


def get_s3_bucket_policies(region):
    s3 = s.client('s3',region_name=region)
    buckets = s3.list_buckets().get('Buckets')
    logger.info(f"Found {len(buckets)} buckets")

    bucket_policies = {}
    for bucket in buckets:
        bucket_name = bucket['Name']

        # Need to determine the location constraint for S3 buckets, to determine which region the bucket policy can be retrieved from
        location = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
        if location == None:
            location = 'us-east-1'
        # logger.debug("[S3] Bucket %s has location constraint %s" % (bucket_name,location))
        s3 = s.client('s3',region_name=location)
        try:
            bucket_policies[bucket_name] = json.loads(s3.get_bucket_policy(Bucket=bucket_name,).get('Policy'))
            logger.debug(json.dumps(bucket_policies[bucket_name]))
        except s3.exceptions.ClientError as e:
            logger.warning("[S3] Unexpected error: %s" % e)
    write_output(f"{account_id}-s3_bucket_policies.json",bucket_policies)


def get_sqs_access_policies(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('sqs')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    queue_policies = []

    for region in regions:
        sqs = s.client('sqs',region_name=region)
        try:
            queues = sqs.list_queues().get('QueueUrls')
        except sqs.exceptions.ClientError as e:
            logging.warning(f"[SQS] Unexpected error: {e}")
            continue
        
        # Make sure there are queues for the region
        if not queues:
            logger.info(f"No SQS queues in {region}")
            continue

        logger.info(f"Found {len(queues)} SQS queues in {region}")
        for queue in queues:
            try:
                data = {
                    'SQS Queue': queue,
                    'Region': region,
                    'Policy': json.loads(sqs.get_queue_attributes(QueueUrl=queue,AttributeNames=['Policy']).get('Attributes').get('Policy'))
                }
                queue_policies.append(data)
                logger.debug(json.dumps(data))
            except sqs.exceptions.ClientError as e:
                logger.warning("[SQS] Unexpected error: {e}")
    write_output(f"{account_id}-sqs_access_policies.json",queue_policies)
    # Analysis Ideas
    # Get a list of trusted AWS principals: cat 123456789012-sqs_access_policies.json | jq -r '.[].Policy.Statement[].Principal'  | more 
    # View access policies allowing access to a principal: cat 123456789012-sqs_access_policies.json | jq '.[] | select(.Policy.Statement[].Principal.AWS=="arn:aws:iam::123456789012:root")' | more

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

get_lambda_policies(specific_region=args.region)
get_sqs_access_policies(specific_region=args.region)
get_cloudwatch_log_policies(specific_region=args.region)