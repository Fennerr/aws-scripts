#!/usr/bin/env python3
from distutils.command.config import config
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
    save_data(f"{account_id}-cloudwatch_log_policies.json",policies)

def get_ecr_repository_policies(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('ecr')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    policies = []

    for region in regions:
        ecr = s.client('ecr',region_name=region)
        try:
            ecr_respositories = ecr.describe_repositories()["repositories"]
        except ecr.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue

        ecr_respositories = []
        try:
            response = ecr.describe_repositories()
            ecr_respositories.extend(response["repositories"])
            while 'nextToken' in response.keys():
                response = ecr.describe_repositories(nextToken = response['nextToken'])
                ecr_respositories.extend(response['repositories'])
        except ecr.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue
        
        if not ecr_respositories:
            logger.info(f"No ECR respositories in {region}")
            continue

        logger.info(f"Found {len(ecr_respositories)} ECR respositories in {region}")

        for ecr_respository in ecr_respositories:
            respoitory_name = ecr_respository.get("repositoryName")
            try:
                data = {
                    'ECR Repository': respoitory_name,
                    'Region': region,
                    'Policy': json.loads(ecr.get_repository_policy(repositoryName=respoitory_name).get('Policy'))
                }
                policies.append(data)
                logger.debug(f"{respoitory_name} has the following access policy defined")
                logger.debug(json.dumps(data))
            except ecr.exceptions.RepositoryPolicyNotFoundException:
                logger.debug(f"{respoitory_name} does not have an access policy defined")
                continue
    save_data(f"{account_id}-ecr_respository_policies.json",policies)

def get_guardduty_detector_configurations(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('guardduty')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    configurations = []

    for region in regions:
        guardduty = s.client('guardduty',region_name=region)
        try:
            guardduty_detector_ids = guardduty.list_detectors()["DetectorIds"]
        except guardduty.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue
        
        if not guardduty_detector_ids:
            logger.info(f"No GuardDuty detectors in {region}")
            continue

        logger.info(f"Found {len(guardduty_detector_ids)} GuardDuty detectors in {region}")

        for guardduty_detector_id in guardduty_detector_ids:
            configuration = guardduty.get_detector(DetectorId=guardduty_detector_id)
            del configuration['ResponseMetadata']
            try:
                data = {
                    'GuardDuty Detector': guardduty_detector_id,
                    'Region': region,
                    'Configuration': configuration
                }
                configurations.append(data)
                logger.debug(f"{region} - {guardduty_detector_id} has the following access policy defined")
                logger.debug(json.dumps(data))
            except guardduty.exceptions.ClientError as e:
                logger.warning("[GuardDuty] Unexpected error: %s" % e)
                continue
    save_data(f"{account_id}-guardduty_detector_configurations.json",configurations)

def get_iam_role_trust_policies(specific_region):
    if specific_region:
        region_name = specific_region
    else:
        region_name = 'us-east-1'
    iam = s.client('iam',region_name=region_name)

    
    roles = []
    response = iam.list_roles()
    roles.extend(response['Roles'])
    while 'Marker' in response.keys():
        response = iam.list_roles(Marker = response['Marker'])
        roles.extend(response['Roles'])
    logger.info(f"Found {len(roles)} roles")

    role_trust_policies = {}
    for role in roles:
        role_name = role.get('RoleName')
        try:
            role_trust_policies[role_name] = iam.get_role(RoleName=role_name).get('Role').get('AssumeRolePolicyDocument')
            logger.debug(f"{role_name} has the following trust policy defined")
            logger.debug(json.dumps(role_trust_policies[role_name]))
        except iam.exceptions.ClientError as e:
            logger.warning("[IAM] Unexpected error: %s" % e)
    save_data(f"{account_id}-iam_role_trust_policies.json",role_trust_policies)

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
    save_data(f"{account_id}-lambda_policies.json",policies)

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
    save_data(f"{account_id}-s3_bucket_policies.json",bucket_policies)

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
    save_data(f"{account_id}-sqs_access_policies.json",queue_policies)
    # Analysis Ideash
    # Get a list of trusted AWS principals: cat 123456789012-sqs_access_policies.json | jq -r '.[].Policy.Statement[].Principal'  | more 
    # View access policies allowing access to a principal: cat 123456789012-sqs_access_policies.json | jq '.[] | select(.Policy.Statement[].Principal.AWS=="arn:aws:iam::123456789012:root")' | more

def get_ecs_task_definitions(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('ecs')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    
    definitions = []

    for region in regions:
        logger.debug(f"Enumerating ECS Task Difinitions for {region}")
        ecs = s.client('ecs',region_name=region)
        task_definition_arns = []
        try:
            response = ecs.list_task_definitions()
            task_definition_arns.extend(response['taskDefinitionArns'])
            while 'nextToken' in response.keys():
                response = ecs.list_task_definitions(nextToken = response['nextToken'])
                task_definition_arns.extend(response['taskDefinitionArns'])
        except ecs.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue

        if not task_definition_arns:
            logger.info(f"No ECS Task Definitions in {region}")
            continue

        logger.info(f"Found {len(task_definition_arns)} ECS Task Definitions in {region}")

        for task_definition_arn in task_definition_arns:
            task_definition = ecs.describe_task_definition(taskDefinition=task_definition_arn)['taskDefinition']
            try:
                data = {
                    'Task Definition ARN': task_definition_arn,
                    'Region': region,
                    'Policy': task_definition
                }
                definitions.append(data)
                logger.debug(data)
            except ecs.exceptions.ResourceNotFoundException:
                continue
    save_data(f"{account_id}-ecs-task_definitions.json",definitions)


def check_ecs_exec_enabled(specific_region):
    if specific_region == None:
        regions = s.get_available_regions('ecs')
        regions = [i for i in regions if i not in not_allowed_regions]
    else:
        regions = [specific_region]
    
    total_task_data = []
    for region in regions:
        ecs = s.client('ecs',region_name=region)
        clusters = ecs.list_clusters()['clusterArns']
        for cluster in clusters:
            tasks = ecs.list_tasks(cluster=cluster)['taskArns']
            if not tasks:
                continue
            # for task in tasks:
            task_data = ecs.describe_tasks(tasks=tasks,cluster=cluster)['tasks']
            for individual_task_data in task_data:
                if "enableExecuteCommand" in individual_task_data.keys():
                    print(f"Looks like ECS exec is enabled for cluster {cluster}")
                for container_definition in individual_task_data['containers']:
                    if not "managedAgents" in container_definition.keys():
                        continue
                    for managed_agent in container_definition['managedAgents']:
                        if managed_agent["name"] == "ExecuteCommandAgent":
                            print("Found an ECS container with the ECS Exec Managed Agent on it")
                            print(task_data)
                            continue    
            print(f"Nothing found for {cluster}")
        total_task_data.append(task_data)

    save_data(f"{account_id}-ecs-task_data.json",total_task_data)


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
else:
    not_allowed_regions = []

# get_lambda_policies(specific_region=args.region)
# get_sqs_access_policies(specific_region=args.region)
# get_cloudwatch_log_policies(specific_region=args.region)
get_ecr_repository_policies(specific_region=args.region)
# get_iam_role_trust_policies(specific_region=args.region)
# get_guardduty_detector_configurations(specific_region=args.region)
# get_ecs_task_definitions(specific_region=args.region)