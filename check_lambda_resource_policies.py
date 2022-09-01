#!/usr/bin/env python3
import profile
import sys
sys.path = ['.'] + sys.path
sys.path = ['./modules'] + sys.path
import boto3
import configparser
import argparse
import json
from os.path import expanduser
from botocore.config import Config
from botocore.exceptions import ClientError
import botocore.exceptions
from datetime import datetime
import logging

# Input Variables
parser = argparse.ArgumentParser()
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use")
optionalNamed.add_argument("--region",default='af-south-1',type=str,help="The default region to use (defaults to af-south-1)")
optionalNamed.add_argument("--log",default='warning',type=str,help="The logging level (debug,info,warning,error,critical)")

def write_output(filename,results):
    with open(filename, 'w') as outputfile:
        json.dump(results, outputfile)


def get_lambda_policies(profile='default'):
    s = boto3.session.Session(profile_name=profile)
    regions = s.get_available_regions('lambda')
    policies = {}
    for region in regions:
        lc = s.client('lambda',region_name=region)
        try:
            lambda_functions = lc.list_functions()["Functions"]
        except lc.exceptions.ClientError as e:
            logging.warning("Unexpected error for region %s: %s" % (region,e))
            continue
        
        if len(lambda_functions) == 0:
            continue
        for lambda_function in lambda_functions:
            function_name = lambda_function.get("FunctionName")
            try:
                policies[function_name] = json.loads(lc.get_policy(FunctionName=lambda_function.get("FunctionName")).get('Policy'))
            except lc.exceptions.ResourceNotFoundException:
                continue
    write_output('lambda_policies.json',policies)


def get_s3_bucket_policies(region,profile='default'):
    s = boto3.session.Session(profile_name=profile)
    s3 = s.client('s3',region_name=region)
    buckets = s3.list_buckets().get('Buckets')
    bucket_policies = {}
    for bucket in buckets:
        bucket_name = bucket['Name']
        location = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
        if location == None:
            location = 'us-east-1'
        logger.debug("[S3] Bucket %s has location constraint %s" % (bucket_name,location))
        s3 = s.client('s3',region_name=location)
        try:
            bucket_policies[bucket_name] = json.loads(s3.get_bucket_policy(Bucket=bucket_name,).get('Policy'))
            logger.debug(json.dumps(bucket_policies[bucket_name]))
        except s3.exceptions.ClientError as e:
            logger.warning("[S3] Unexpected error: %s" % e)
    write_output('s3_bucket_policies.json',bucket_policies)
            
    exit()
    regions = s.get_available_regions('lambda')
    policies = {}
    for region in regions:
        lc = s.client('lambda',region_name=region)
        try:
            lambda_functions = lc.list_functions()["Functions"]
        except lc.exceptions.ClientError as e:
            print("Unexpected error for region %s: %s" % (region,e))
            continue
        
        if len(lambda_functions) == 0:
            continue
        for lambda_function in lambda_functions:
            function_name = lambda_function.get("FunctionName")
            try:
                policies[function_name] = json.loads(lc.get_policy(FunctionName=lambda_function.get("FunctionName")).get('Policy'))
            except lc.exceptions.ResourceNotFoundException:
                continue
    write_output('lambda_policies.json',policies)

# Get the passed arguements
args = parser.parse_args()


numeric_level = getattr(logging, args.log.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % args.log)
logger = logging.getLogger(__name__)
logger.setLevel(numeric_level)

ch = logging.StreamHandler()
logger.addHandler(ch)
# logging.basicConfig(level=numeric_level)

get_s3_bucket_policies(profile=args.profile,region=args.region)