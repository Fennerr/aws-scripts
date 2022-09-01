#!/usr/bin/env python3
import sys
sys.path = ['.'] + sys.path
sys.path = ['./modules'] + sys.path
import boto3
import configparser
import argparse
from os.path import expanduser
from botocore.config import Config
from datetime import datetime
##########################################################################
# awsconfigfile: The file where this script will store the credentials
awsconfigfile = '/.aws/credentials'

# Input Variables
parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use when assuming the role",required=True)
requiredNamed.add_argument("-s","--session-profile",type=str,help="The name of the profile which the credentials will be saved to",required=True)
requiredNamed.add_argument("-r","--role-arn",type=str,help="The role ARN of the role that will be assumed",required=True)
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-d","--duration",default=3600,type=int,help="The session duration to assume the role for (default to 3600 seconds)")
optionalNamed.add_argument("--region",default='af-south-1',type=str,help="The default region for the session profile (defaults to af-south-1)")
optionalNamed.add_argument("--output-format",default='json',type=str,help="The default output format for the session profile (defaults to json) ")
optionalNamed.add_argument("--role-session-name",default='mwr_{}'.format(datetime.now().strftime("%Y-%m-%d_%H-%M-%S")),type=str,help="The role session name (defaults to mwr_Y-M-D_h-m-s)")

# Parse the variables into an options dict
args = parser.parse_args()
options = {}
options['RoleArn']=args.role_arn
options['DurationSeconds']=args.duration
options['RoleSessionName']=args.role_session_name

# Fetch the session tokens
session = boto3.Session(profile_name=args.profile)
token = session.client('sts',config=Config()).assume_role(**options)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into the credentials file
if not config.has_section(args.session_profile):
    config.add_section(args.session_profile)

config.set(args.session_profile, 'output', args.output_format)
config.set(args.session_profile, 'region', args.region)
config.set(args.session_profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set(args.session_profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set(args.session_profile, 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print ('\n\n----------------------------------------------------------------')
print ('Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'.format(filename,args.session_profile))
print ('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
print ('After this time, you may safely rerun this script to refresh your access key pair.')
print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(args.session_profile))
print ('----------------------------------------------------------------\n\n')
