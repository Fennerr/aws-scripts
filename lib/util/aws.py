import boto3

from util.args import args
from util.logging import logger

########################
# Helper Functions


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


########################
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
